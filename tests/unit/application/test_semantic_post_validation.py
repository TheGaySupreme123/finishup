from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import replace

import pytest

from builders.policy_cases import (
    BASE_COVERAGE,
    FRONTIER,
    act,
    clm,
    evt,
    finding_record,
    fnd,
    make_case,
    obl,
    record,
    res,
)
from yoetz.application.check import (
    SEMANTIC_REJECTED_HIDDEN_SOURCE_CLAIM,
    SEMANTIC_REJECTED_REF_NOT_CARRIED,
    SEMANTIC_REJECTED_REF_OUTSIDE_CASE,
    SEMANTIC_REJECTED_SUBJECTS_OVER_LIMIT,
    SemanticJudgmentRejected,
    SemanticJudgmentReview,
    validate_semantic_judgment,
)
from yoetz.domain.events import (
    ResponseDisposition,
    ResponseRecordedPayload,
    ResultOutcome,
    ResultRecordedPayload,
)
from yoetz.domain.findings import (
    Finding,
    FindingKind,
    FindingOrigin,
    SamplingParams,
    SemanticDispatchKind,
    SemanticProvenance,
)
from yoetz.kernel.deterministic_checks import DeterministicCase
from yoetz.ports.semantic import (
    PriorFindingVerdict,
    ReviewerChallenge,
    SemanticJudgment,
    VerifiedReviewItem,
)
from yoetz.protocol.models import SemanticReason, SemanticStatus

_DIGEST = "sha256:" + "a" * 64
_INVENTED = "clm_20000000-0000-4000-8000-000000000099"


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
        semantic_attempt_id="att_20000000-0000-4000-8000-000000000001",
        dispatch_kind=SemanticDispatchKind.EXTERNAL,
        privacy_receipt_id="egr_20000000-0000-4000-8000-000000000001",
        status=SemanticStatus.SUCCEEDED,
        reason=SemanticReason.SEMANTIC_COMPLETED,
        provider_request_id="fake-1",
        egress_authorization_id="aut_20000000-0000-4000-8000-000000000001",
        request_commitment="hmac-sha256:" + "b" * 64,
    )


def _challenge(
    *refs: str,
    summary: str = "Evidence gap",
    snippet: str | None = None,
) -> ReviewerChallenge:
    return ReviewerChallenge(
        FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
        summary,
        tuple(sorted(refs)),
        "The claim lacks a recorded basis.",
        "The claim may remain unresolved.",
        "Main agent: provide evidence for the claim.",
        "provide_evidence",
        "The missing material may exist outside the case.",
        snippet,
    )


def test_reviewer_snippets_use_exact_provider_bound_text() -> None:
    case = make_case(extra_refs=(clm(1),))
    judgment = SemanticJudgment(
        "challenges_returned",
        (_challenge(str(clm(1)), snippet="sent-safe-row"),),
    )
    accepted = validate_semantic_judgment(
        case,
        (),
        judgment,
        _provenance(),
        expected_frontier=case.frontier,
        citable_refs=frozenset({str(clm(1))}),
        provider_input_text_by_ref={str(clm(1)): ("sent-safe-row",)},
    )
    assert accepted.challenges_rejected == 0
    assert accepted.challenges_returned == 1

    partial_case = make_case(extra_refs=(clm(1), clm(2)))
    partial_provider_text = validate_semantic_judgment(
        partial_case,
        (),
        SemanticJudgment(
            "challenges_returned",
            (_challenge(str(clm(1)), str(clm(2)), snippet="sent-safe-row"),),
        ),
        _provenance(),
        expected_frontier=partial_case.frontier,
        citable_refs=frozenset({str(clm(1)), str(clm(2))}),
        provider_input_text_by_ref={str(clm(1)): ("sent-safe-row",)},
    )
    # A cited ref whose content was not sent is removed; the challenge stands on the ref that was
    # sent instead of being discarded whole (TB4 tb4v1 atrx-vep-crispr, issue #976).
    assert partial_provider_text.challenges_rejected == 0
    assert partial_provider_text.refs_reduced == 1
    assert partial_provider_text.snippets_rejected == 0
    assert len(partial_provider_text.candidates) == 1
    assert partial_provider_text.candidates[0].subject_refs == (clm(1),)

    rejected = validate_semantic_judgment(
        case,
        (),
        judgment,
        _provenance(),
        expected_frontier=case.frontier,
        citable_refs=frozenset({str(clm(1))}),
        provider_input_text_by_ref={str(clm(1)): ("different-provider-row",)},
    )
    # The cited ref was sent, so the challenge stands; only its unproven quote is removed and
    # disclosed as a snippet loss (TB4 tb4f1 ks-solver-cpp, issue #976).
    assert rejected.challenges_rejected == 0
    assert len(rejected.candidates) == 1
    assert rejected.candidates[0].challenge is not None
    assert rejected.candidates[0].challenge.snippet is None
    assert rejected.snippets_rejected == 1

    # A quote that matches the sent text only after whitespace normalization is proven, and is
    # recorded as the verbatim sent span rather than the reviewer's reflowed spelling.
    reflowed = validate_semantic_judgment(
        case,
        (),
        SemanticJudgment(
            "challenges_returned",
            (_challenge(str(clm(1)), snippet="first line   second line"),),
        ),
        _provenance(),
        expected_frontier=case.frontier,
        citable_refs=frozenset({str(clm(1))}),
        provider_input_text_by_ref={str(clm(1)): ("row: first line\n second line end",)},
    )
    assert reflowed.snippets_rejected == 0
    assert reflowed.candidates[0].challenge is not None
    assert reflowed.candidates[0].challenge.snippet == "first line\n second line"

    recovered_without_text = validate_semantic_judgment(
        case,
        (),
        judgment,
        _provenance(),
        expected_frontier=case.frontier,
        citable_refs=frozenset({str(clm(1))}),
        provider_input_text_by_ref=None,
    )
    # Without the provider-bound text index nothing is proven sent: the challenge mints no
    # finding, but it is counted under its own reason and surfaced as an advisory concern.
    assert recovered_without_text.candidates == ()
    assert recovered_without_text.rejected_by_reason == ((SEMANTIC_REJECTED_REF_NOT_CARRIED, 1),)
    assert recovered_without_text.snippets_rejected == 0
    assert "Evidence gap" in recovered_without_text.review_summary
    assert "sent-safe-row" not in recovered_without_text.review_summary


@pytest.mark.parametrize("conclusion", ["no_material_discrepancy", "challenges_returned"])
def test_dropped_verified_rows_are_not_counted_as_rejected_challenges(conclusion: str) -> None:
    """A verified row the fence drops is a disclosed snippet loss, never a rejected challenge.

    Regression: dropped verified rows were folded into the snippet-rejected *challenge* count,
    so returned != accepted + rejected + suppressed and every such review failed the check with
    a non-retryable internal error (a cited ref with no provider-bound text, or an inexact quote).
    """

    case = make_case(extra_refs=(clm(1), obl(1)))
    challenges = (
        (_challenge(str(clm(1)), snippet="sent-safe-row"),)
        if conclusion == "challenges_returned"
        else ()
    )
    judgment = SemanticJudgment(
        conclusion,  # pyright: ignore[reportArgumentType]
        challenges,
        review_summary="Checked the claim and the obligation.",
        verified=(
            VerifiedReviewItem("Claim holds", "supported", (str(clm(1)),), "sent-safe-row"),
            # Citable but never sent as text: the row is dropped.
            VerifiedReviewItem("Obligation met", "not_assessable", (str(obl(1)),)),
            # Quote that is not an exact packet substring: the row is dropped.
            VerifiedReviewItem("Claim quoted", "supported", (str(clm(1)),), "invented quote"),
        ),
    )
    review = validate_semantic_judgment(
        case,
        (),
        judgment,
        _provenance(),
        expected_frontier=case.frontier,
        citable_refs=frozenset({str(clm(1)), str(obl(1))}),
        provider_input_text_by_ref={str(clm(1)): ("sent-safe-row",)},
    )
    assert review.challenges_rejected == 0
    assert review.challenges_returned == len(challenges)
    assert len(review.candidates) == len(challenges)
    # The quote loss is a snippet loss; the row citing an unsent ref is a disclosed ref loss.
    assert review.snippets_rejected == 1
    assert review.refs_reduced == 1
    assert [item.requirement_or_claim for item in review.verified] == ["Claim holds"]


def test_semantic_judgment_accepts_only_frozen_refs_and_derives_policy() -> None:
    case = make_case(extra_refs=(clm(1),))
    judgment = SemanticJudgment("challenges_returned", (_challenge(str(clm(1))),))

    review = validate_semantic_judgment(
        case,
        (),
        judgment,
        _provenance(),
        expected_frontier=case.frontier,
    )

    assert len(review.candidates) == 1
    assert review.candidates[0].subject_refs == (clm(1),)
    assert review.candidates[0].policy_id == "work-integrity"
    assert review.candidates[0].policy_version == "0.3.0"
    assert review.challenges_returned == 1
    assert review.rejected_by_reason == ()


def test_one_bad_challenge_does_not_discard_the_others() -> None:
    """The fence is per challenge, so an invented ref costs its own challenge and nothing else.

    Regression for the live failure: three returned challenges where the middle one cited an
    invented ref used to discard all three — and, because the raise escaped the coordinator, the
    entire check with them.
    """

    case = make_case(extra_refs=(clm(1), clm(2)))
    judgment = SemanticJudgment(
        "challenges_returned",
        (
            _challenge(str(clm(1)), summary="First"),
            _challenge(_INVENTED, summary="Second"),
            _challenge(str(clm(2)), summary="Third"),
        ),
    )

    review = validate_semantic_judgment(
        case,
        (),
        judgment,
        _provenance(),
        expected_frontier=case.frontier,
    )

    assert [candidate.summary for candidate in review.candidates] == ["First", "Third"]
    assert review.challenges_returned == 3
    assert review.rejected_by_reason == ((SEMANTIC_REJECTED_REF_OUTSIDE_CASE, 1),)
    assert review.challenges_rejected == 1


def test_hidden_source_claim_is_counted_and_only_costs_its_own_challenge() -> None:
    """The "nothing changed" claim over a withheld basis is still refused, one challenge at a time."""

    case = make_case(
        extra_refs=(clm(1), clm(2)),
        coverage_overrides={clm(1): replace(BASE_COVERAGE, known_gaps=("missing_ref",))},
    )
    hidden = ReviewerChallenge(
        FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
        "Claims no change",
        (str(clm(1)),),
        "The file is unchanged.",
        "Nothing was modified.",
        "Main agent: no further action required.",
        "state_unresolved_limitation",
        "The excerpt was never disclosed.",
    )
    judgment = SemanticJudgment(
        "challenges_returned",
        (hidden, _challenge(str(clm(2)), summary="Real")),
    )

    review = validate_semantic_judgment(
        case,
        (),
        judgment,
        _provenance(),
        expected_frontier=case.frontier,
    )

    assert [candidate.summary for candidate in review.candidates] == ["Real"]
    assert review.rejected_by_reason == ((SEMANTIC_REJECTED_HIDDEN_SOURCE_CLAIM, 1),)


def test_structural_failure_raises_the_narrow_rejection_the_commit_path_catches() -> None:
    case = make_case(extra_refs=(clm(1),))

    with pytest.raises(SemanticJudgmentRejected, match="semantic_judgment_invalid"):
        validate_semantic_judgment(
            case,
            (),
            SemanticJudgment("challenges_returned", (_challenge(str(clm(1))),)),
            _provenance(),
            expected_frontier=type(case.frontier)(99, "sha256:" + "c" * 64),
        )


def test_no_material_discrepancy_returns_no_semantic_candidate() -> None:
    case = make_case(extra_refs=(clm(1),))

    review = validate_semantic_judgment(
        case,
        (),
        SemanticJudgment("no_material_discrepancy", ()),
        _provenance(),
        expected_frontier=case.frontier,
    )

    assert review.candidates == ()
    assert review.challenges_returned == 0
    assert review.rejected_by_reason == ()


def test_rejection_counts_aggregate_and_reasons_sort_deterministically() -> None:
    """Repeated drops sum, and two reasons come back in one stable order.

    With a single rejection under a single reason, neither the counter nor the sort is observable;
    a mixed judgment pins both. Deterministic reproducibility is the point — the same judgment
    must always produce the same accounting.
    """

    case = make_case(
        extra_refs=(clm(1), clm(2)),
        coverage_overrides={clm(1): replace(BASE_COVERAGE, known_gaps=("missing_ref",))},
    )
    hidden = ReviewerChallenge(
        FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
        "Claims no change",
        (str(clm(1)),),
        "The file is unchanged.",
        "Nothing was modified.",
        "Main agent: no further action required.",
        "state_unresolved_limitation",
        "The excerpt was never disclosed.",
    )
    judgment = SemanticJudgment(
        "challenges_returned",
        (
            _challenge(_INVENTED, summary="First invented"),
            hidden,
            _challenge(str(clm(2)), summary="Real"),
        ),
    )

    review = validate_semantic_judgment(
        case,
        (),
        judgment,
        _provenance(),
        expected_frontier=case.frontier,
    )

    assert [candidate.summary for candidate in review.candidates] == ["Real"]
    assert review.challenges_returned == 3
    assert review.challenges_rejected == 2
    # Sorted by ASCII reason token, so hidden_source_claim precedes ref_outside_case.
    assert review.rejected_by_reason == (
        (SEMANTIC_REJECTED_HIDDEN_SOURCE_CLAIM, 1),
        (SEMANTIC_REJECTED_REF_OUTSIDE_CASE, 1),
    )
    assert review.challenges_returned == len(review.candidates) + review.challenges_rejected


def test_review_rejects_accounting_that_does_not_add_up() -> None:
    """The value type owns the reconciliation the diagnostic reports."""

    with pytest.raises(ValueError, match="semantic_judgment_review_invalid"):
        SemanticJudgmentReview((), 3, ((SEMANTIC_REJECTED_REF_OUTSIDE_CASE, 1),))


def _recorded_semantic_finding(number: int, *subjects: str) -> Finding:
    return Finding(
        finding_id=fnd(number),
        kind=FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
        origin=FindingOrigin.SEMANTIC_MODEL_DERIVED,
        priority=1,
        summary="Required llvmlite 0.46.0 verification remains open.",
        detail="Make one concrete authorized attempt to obtain llvmlite 0.46.0.",
        subject_refs=tuple(sorted(subjects)),  # type: ignore[arg-type]
        policy_id="work-integrity",
        policy_version="0.1.0",
        subject_frontier=FRONTIER,
        coverage=BASE_COVERAGE,
        provenance=_provenance(),
    )


def test_challenge_citing_a_recorded_prior_finding_resolves_to_its_subjects() -> None:
    """citable_refs offers every recorded fnd_ id, so citing one must not drop the challenge.

    Regression for the httpx/katex v2 rounds (issue #905): the reviewer named the earlier finding
    its re-raise concerned, the fence only knew this check's local findings, and the challenge
    was dropped as ``ref_outside_case`` with ``semantic_challenges_rejected`` left on the check.
    """

    prior = _recorded_semantic_finding(1, str(obl(7)), str(clm(1)))
    case = make_case(
        findings={fnd(1): finding_record(prior, 5)},
        extra_refs=(clm(1), clm(2), obl(7)),
    )
    judgment = SemanticJudgment(
        "challenges_returned",
        (_challenge(str(fnd(1)), str(clm(2)), summary="Still open after newer material"),),
    )

    review = validate_semantic_judgment(
        case,
        (),
        judgment,
        _provenance(),
        expected_frontier=case.frontier,
    )

    assert review.rejected_by_reason == ()
    assert len(review.candidates) == 1
    assert review.candidates[0].subject_refs == tuple(
        sorted((clm(1), clm(2), obl(7)), key=lambda ref: str(ref).encode())
    )


def test_cited_prior_finding_must_be_readable_and_inside_the_frozen_fence() -> None:
    """Only the fnd_ lookup widened: an unreadable, unknown, or out-of-fence finding still drops."""

    prior = _recorded_semantic_finding(1, str(clm(1)))
    redacted = replace(finding_record(prior, 5), payload=None, redacted=True)
    unreadable = make_case(findings={fnd(1): redacted}, extra_refs=(clm(1), clm(2)))
    unknown = make_case(extra_refs=(clm(1), clm(2)))
    for case, cited in ((unreadable, fnd(1)), (unknown, fnd(9))):
        review = validate_semantic_judgment(
            case,
            (),
            SemanticJudgment("challenges_returned", (_challenge(str(cited), str(clm(2))),)),
            _provenance(),
            expected_frontier=case.frontier,
        )
        assert review.candidates == ()
        assert review.rejected_by_reason == ((SEMANTIC_REJECTED_REF_OUTSIDE_CASE, 1),)


def test_challenge_whose_resolved_subjects_exceed_the_finding_bound_is_counted_not_fatal() -> None:
    """Several cited findings can union past a finding's 64 subjects; that costs one challenge."""

    wide = tuple(str(clm(number)) for number in range(1, 41))
    wider = tuple(str(clm(number)) for number in range(41, 81))
    first = _recorded_semantic_finding(1, *wide)
    second = _recorded_semantic_finding(2, *wider)
    case = make_case(
        findings={fnd(1): finding_record(first, 5), fnd(2): finding_record(second, 6)},
        extra_refs=(clm(90),),
    )
    judgment = SemanticJudgment(
        "challenges_returned",
        (
            _challenge(str(fnd(1)), str(fnd(2)), summary="Too wide"),
            _challenge(str(clm(90)), summary="Kept"),
        ),
    )

    review = validate_semantic_judgment(
        case,
        (),
        judgment,
        _provenance(),
        expected_frontier=case.frontier,
    )

    assert [candidate.summary for candidate in review.candidates] == ["Kept"]
    assert review.rejected_by_reason == ((SEMANTIC_REJECTED_SUBJECTS_OVER_LIMIT, 1),)


def _verdict(number: int, kind: str, *refs: str) -> PriorFindingVerdict:
    return PriorFindingVerdict(str(fnd(number)), kind, tuple(sorted(refs)))  # type: ignore[arg-type]


def _dialogue_case() -> DeterministicCase:
    """kea shape: a real defect raised at 5, repaired with a regression result recorded at 9."""

    older = record(
        ResultRecordedPayload(res(1), act(1), ResultOutcome.SUCCESS, summary="before"), 3
    )
    repair = record(
        ResultRecordedPayload(res(2), act(2), ResultOutcome.SUCCESS, summary="regression"), 9
    )
    rejected = ResponseRecordedPayload(
        finding_id=fnd(3),
        finding_frontier=FRONTIER,
        disposition=ResponseDisposition.REJECTED,
        reason="The task requires plain text without a tail under Ascii.",
    )
    return make_case(
        results={res(1): older, res(2): repair},
        findings={
            fnd(1): finding_record(_recorded_semantic_finding(1, str(obl(1))), 5),
            fnd(2): finding_record(_recorded_semantic_finding(2, str(obl(2))), 6),
            fnd(3): finding_record(_recorded_semantic_finding(3, str(obl(3))), 7),
            fnd(4): finding_record(
                replace(
                    _recorded_semantic_finding(4, str(obl(4))),
                    origin=FindingOrigin.DETERMINISTIC,
                    provenance=None,
                ),
                8,
            ),
        },
        responses={fnd(3): record(rejected, 8)},
        extra_refs=(obl(1), obl(2), obl(3), obl(4)),
    )


def test_prior_finding_rulings_are_admitted_only_with_their_own_support() -> None:
    """A hallucinated ``fixed`` must not close a real defect (issue #905)."""

    case = _dialogue_case()
    judgment = SemanticJudgment(
        "insufficient_packet",
        (),
        (
            _verdict(1, "fixed", str(res(2))),  # cites the repair recorded after the finding
            _verdict(2, "fixed", str(res(1))),  # cites only material older than the finding
            _verdict(3, "withdrawn"),  # accepts a readable rejected response
            _verdict(4, "still_present", str(obl(4))),  # a local finding is not the reviewer's
        ),
    )

    review = validate_semantic_judgment(
        case, (), judgment, _provenance(), expected_frontier=case.frontier
    )

    assert [(str(item.finding_id), item.verdict) for item in review.verdicts] == [
        (str(fnd(1)), "fixed"),
        (str(fnd(2)), "unassessable"),
        (str(fnd(3)), "withdrawn"),
    ]
    # fnd(2)'s unsupported fixed is unsupported. A ruling on the local fnd(4) is set aside: its
    # answer travels as non-rulable context and the ruling is only counted (issue #976).
    assert review.verdicts_unsupported == 1
    assert review.verdicts_set_aside == 1
    assert review.candidates == ()


def test_a_ruling_resting_only_on_a_local_finding_cannot_close_anything() -> None:
    """Citing a local (deterministic) finding is not repair material (issue #976).

    A ``fixed`` ruling whose only support is the local fnd(4) is unsupported and records as
    ``unassessable``; a ``still_present`` ruling citing it keeps its finding open; neither rules on
    or resolves the local finding itself, and no candidate is minted.
    """

    case = _dialogue_case()
    judgment = SemanticJudgment(
        "no_material_discrepancy",
        (),
        (
            _verdict(1, "fixed", str(fnd(4))),
            _verdict(2, "still_present", str(fnd(4))),
        ),
    )

    review = validate_semantic_judgment(
        case, (), judgment, _provenance(), expected_frontier=case.frontier
    )

    assert [(str(item.finding_id), item.verdict) for item in review.verdicts] == [
        (str(fnd(1)), "unassessable"),
        (str(fnd(2)), "still_present"),
    ]
    assert all(item.finding_id != fnd(4) for item in review.verdicts)
    assert review.verdicts_unsupported == 1
    assert review.candidates == ()


def test_rulings_without_cited_material_or_a_rejection_to_accept_are_unassessable() -> None:
    case = _dialogue_case()
    judgment = SemanticJudgment(
        "no_material_discrepancy",
        (),
        (
            _verdict(1, "still_present"),
            _verdict(2, "withdrawn"),
            _verdict(3, "unassessable"),
            _verdict(9, "fixed", str(res(2))),
        ),
    )

    review = validate_semantic_judgment(
        case, (), judgment, _provenance(), expected_frontier=case.frontier
    )

    assert [(str(item.finding_id), item.verdict) for item in review.verdicts] == [
        (str(fnd(1)), "unassessable"),
        (str(fnd(2)), "unassessable"),
        # Issue #1020: fnd(3) was rejected with a reason; an unassessable ruling citing nothing
        # newer is the standing disagreement, not another open round.
        (str(fnd(3)), "disputed_after_rebuttal"),
    ]
    # Two reduced, one outside the fence; an honest unassessable is not counted.
    assert review.verdicts_unsupported == 3


_FOREIGN = "evd_99999999-9999-4999-8999-999999999999"


def _review(
    judgment: SemanticJudgment,
    *,
    prior_finding_refs: frozenset[str] | None = None,
    citable_refs: frozenset[str] | None = None,
    provider_input_text_by_ref: Mapping[str, tuple[str, ...]] | None = None,
) -> SemanticJudgmentReview:
    case = _dialogue_case()
    return validate_semantic_judgment(
        case,
        (),
        judgment,
        _provenance(),
        expected_frontier=case.frontier,
        prior_finding_refs=prior_finding_refs,
        citable_refs=citable_refs,
        provider_input_text_by_ref=provider_input_text_by_ref,
    )


def _rulings(review: SemanticJudgmentReview) -> list[tuple[str, str, tuple[str, ...]]]:
    return [(str(item.finding_id), item.verdict, item.cited_refs) for item in review.verdicts]


def test_a_ruling_that_loses_a_cited_ref_is_unassessable_never_silently_dropped() -> None:
    """A dropped ruling would let its finding close by silence (review of #905)."""

    review = _review(
        SemanticJudgment(
            "no_material_discrepancy",
            (),
            (
                _verdict(1, "still_present", str(obl(1)), _FOREIGN),
                _verdict(2, "fixed", str(res(2)), _FOREIGN),
            ),
        )
    )

    assert _rulings(review) == [
        (str(fnd(1)), "unassessable", (str(obl(1)),)),
        (str(fnd(2)), "unassessable", (str(res(2)),)),
    ]
    assert review.verdicts_unsupported == 2


def test_repeated_rulings_on_one_finding_are_counted_and_conflicts_are_unassessable() -> None:
    review = _review(
        SemanticJudgment(
            "insufficient_packet",
            (),
            (
                _verdict(1, "fixed", str(res(2))),
                _verdict(1, "still_present", str(obl(1))),
                _verdict(2, "still_present", str(obl(2))),
                _verdict(2, "still_present", str(obl(2))),
            ),
        )
    )

    assert _rulings(review) == [
        (str(fnd(1)), "unassessable", ()),
        (str(fnd(2)), "still_present", (str(obl(2)),)),
    ]
    assert review.verdicts_unsupported == 2


def test_withdrawn_needs_a_rejection_not_an_acknowledgement() -> None:
    acknowledged = ResponseRecordedPayload(
        finding_id=fnd(1),
        finding_frontier=FRONTIER,
        disposition=ResponseDisposition.ACKNOWLEDGED,
        evidence_refs=(res(2),),
    )
    base = _dialogue_case()
    case = replace(
        base,
        projection=replace(
            base.projection,
            responses={**base.projection.responses, fnd(1): record(acknowledged, 10)},
        ),
    )
    review = validate_semantic_judgment(
        case,
        (),
        SemanticJudgment("no_material_discrepancy", (), (_verdict(1, "withdrawn"),)),
        _provenance(),
        expected_frontier=case.frontier,
    )

    assert _rulings(review) == [(str(fnd(1)), "unassessable", ())]
    assert review.verdicts_unsupported == 1


def test_rulings_are_fenced_to_the_packet_the_reviewer_was_shown() -> None:
    """A ruling on a finding the prior-findings section never carried stays unassessable (never
    silence), and a ref the packet did not offer as citable cannot carry a ruling."""

    judgment = SemanticJudgment(
        "no_material_discrepancy",
        (),
        (_verdict(1, "fixed", str(res(2))), _verdict(2, "still_present", str(obl(2)))),
    )
    review = _review(
        judgment,
        prior_finding_refs=frozenset({str(fnd(1))}),
        citable_refs=frozenset({str(fnd(1)), str(obl(2))}),
    )

    # fnd(2) was not carried; res(2) was not citable, so fnd(1)'s fixed has nothing left.
    assert _rulings(review) == [
        (str(fnd(1)), "unassessable", ()),
        (str(fnd(2)), "unassessable", (str(obl(2)),)),
    ]
    assert review.verdicts_unsupported == 2


def test_prior_rulings_are_fenced_to_exact_provider_bound_refs() -> None:
    """A composed citable ref cannot support a ruling after privacy drops its provider row."""

    review = _review(
        SemanticJudgment(
            "no_material_discrepancy",
            (),
            (_verdict(1, "fixed", str(res(2))),),
        ),
        prior_finding_refs=frozenset({str(fnd(1))}),
        citable_refs=frozenset({str(fnd(1)), str(res(2))}),
        provider_input_text_by_ref={str(obl(1)): ("a different provider-bound row",)},
    )

    assert _rulings(review) == [(str(fnd(1)), "unassessable", ())]
    assert review.verdicts_unsupported == 1


def test_a_fixed_ruling_on_a_finding_the_same_review_re_raises_is_unassessable() -> None:
    judgment = SemanticJudgment(
        "challenges_returned",
        (_challenge(str(fnd(1)), str(obl(1)), summary="The Map key collision remains"),),
        (_verdict(1, "fixed", str(res(2))),),
    )

    review = _review(judgment)

    assert [candidate.related_finding_ids for candidate in review.candidates] == [(fnd(1),)]
    assert _rulings(review) == [(str(fnd(1)), "unassessable", ())]
    assert review.verdicts_unsupported == 1


def test_rulings_the_normalizer_dropped_are_disclosed_by_the_fence() -> None:
    review = _review(
        SemanticJudgment(
            "no_material_discrepancy",
            (),
            (_verdict(1, "fixed", str(res(2))),),
            prior_finding_verdicts_dropped=2,
        )
    )

    assert _rulings(review) == [(str(fnd(1)), "fixed", (str(res(2)),))]
    assert review.verdicts_unsupported == 2


def _restatement_case(
    obligation_recorded_at: int,
    *,
    repaired: bool = False,
    resolved: bool = False,
    hidden: bool = False,
) -> DeterministicCase:
    """numba shape: one AI-powered finding on an obligation, recorded at sequence 5."""

    from builders.policy_cases import obligation_record
    from yoetz.domain.events import ObligationPublishedPayload, ObligationStatus

    obligation = obligation_record(
        ObligationPublishedPayload(
            obl(1), "Verify with llvmlite 0.46.0", "stencil tests pass", ObligationStatus.OPEN
        ),
        obligation_recorded_at,
    )
    repair = record(
        ResultRecordedPayload(res(2), act(2), ResultOutcome.SUCCESS, summary="regression"), 9
    )
    withheld = replace(BASE_COVERAGE, known_gaps=("captured_object_unavailable",))
    return make_case(
        obligations={obl(1): obligation},
        coverage_overrides={obl(1): withheld} if hidden else None,
        results={res(2): repair} if repaired else None,
        findings={
            fnd(1): finding_record(
                _recorded_semantic_finding(1, str(obl(1))),
                5,
                resolved_by_check_event_id=evt(8) if resolved else None,
            )
        },
    )


def test_a_re_raise_of_a_verified_resolved_finding_is_a_new_item_not_a_restatement() -> None:
    """Done stays done, and a re-raise after verified resolution is a #458 successor, minted.

    Suppressing it would hide a problem the reviewer found again behind a closed row: the
    receipt would read clean with nothing blocking (slice-4 verification D1)."""

    case = _restatement_case(obligation_recorded_at=2, resolved=True)
    review = validate_semantic_judgment(
        case,
        (),
        SemanticJudgment("challenges_returned", (_obligation_challenge(str(obl(1))),)),
        _provenance(),
        expected_frontier=case.frontier,
    )
    assert len(review.candidates) == 1
    assert review.restatements_suppressed == 0
    assert review.verdicts == ()


def _obligation_challenge(*refs: str) -> ReviewerChallenge:
    return replace(
        _challenge(*refs, summary="Required llvmlite 0.46.0 verification remains open"),
        finding_kind=FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
    )


def test_a_restatement_without_newer_material_is_seen_again_and_suppressed() -> None:
    """Three numba restatements must become one item, disclosed, never a silent drop."""

    case = _restatement_case(obligation_recorded_at=2)
    judgment = SemanticJudgment(
        "challenges_returned",
        (_obligation_challenge(str(obl(1))), _obligation_challenge(str(fnd(1)))),
    )

    review = validate_semantic_judgment(
        case, (), judgment, _provenance(), expected_frontier=case.frontier
    )

    assert review.candidates == ()
    assert review.restatements_suppressed == 2
    assert review.rejected_by_reason == ()  # a restatement is not a rejected challenge
    # Suppression never reads as absence: the open item is recorded as still present.
    assert _rulings(review) == [(str(fnd(1)), "still_present", (str(obl(1)),))]


def test_a_restatement_contradicts_an_explicit_fixed_and_leaves_terminal_items_alone() -> None:
    case = _restatement_case(obligation_recorded_at=2)
    repaired = _restatement_case(obligation_recorded_at=2, repaired=True)
    supported = validate_semantic_judgment(
        repaired,
        (),
        SemanticJudgment("no_material_discrepancy", (), (_verdict(1, "fixed", str(res(2))),)),
        _provenance(),
        expected_frontier=repaired.frontier,
    )
    assert _rulings(supported) == [(str(fnd(1)), "fixed", (str(res(2)),))]
    contradicted = validate_semantic_judgment(
        repaired,
        (),
        SemanticJudgment(
            "challenges_returned",
            (_obligation_challenge(str(obl(1))),),
            (_verdict(1, "fixed", str(res(2))),),  # a supported fixed, then restated anyway
        ),
        _provenance(),
        expected_frontier=repaired.frontier,
    )
    assert _rulings(contradicted) == [(str(fnd(1)), "unassessable", ())]
    assert contradicted.restatements_suppressed == 1
    # R3: the contradicted ruling is set aside on its own item, not an unsupported-ruling gap.
    assert (contradicted.verdicts_unsupported, contradicted.verdicts_set_aside) == (0, 1)

    not_done = ResponseRecordedPayload(
        finding_id=fnd(1),
        finding_frontier=FRONTIER,
        disposition=ResponseDisposition.ACKNOWLEDGED_NOT_DONE,
        reason="Out of scope for this task.",
    )
    terminal = replace(
        case, projection=replace(case.projection, responses={fnd(1): record(not_done, 6)})
    )
    review = validate_semantic_judgment(
        terminal,
        (),
        SemanticJudgment("challenges_returned", (_obligation_challenge(str(obl(1))),)),
        _provenance(),
        expected_frontier=terminal.frontier,
    )
    assert review.candidates == () and review.restatements_suppressed == 1
    # A final item is never re-reviewed or reopened, but the re-raise is recorded on it (#980):
    # the reducer folds this ruling into ``settled_reraise_count``, never a review round.
    assert _rulings(review) == [(str(fnd(1)), "still_present", (str(obl(1)),))]


def test_newer_material_or_another_kind_is_a_new_item_not_a_restatement() -> None:
    revised = _restatement_case(obligation_recorded_at=9)  # the obligation changed since
    other_kind = _restatement_case(obligation_recorded_at=2)
    judgments = (
        (revised, _obligation_challenge(str(obl(1)))),
        (other_kind, _challenge(str(obl(1)))),  # claim_without_admissible_evidence
    )
    for case, challenge in judgments:
        review = validate_semantic_judgment(
            case,
            (),
            SemanticJudgment("challenges_returned", (challenge,)),
            _provenance(),
            expected_frontier=case.frontier,
        )
        assert len(review.candidates) == 1
        assert review.restatements_suppressed == 0


def test_a_hidden_source_claim_is_rejected_before_any_restatement_is_recorded() -> None:
    """D5: a challenge the fence rejects must not record ``still_present`` or a review round."""

    case = _restatement_case(obligation_recorded_at=2, hidden=True)
    hidden = replace(
        _obligation_challenge(str(obl(1))),
        discrepancy="The obligation is unchanged.",
    )
    review = validate_semantic_judgment(
        case,
        (),
        SemanticJudgment("challenges_returned", (hidden,)),
        _provenance(),
        expected_frontier=case.frontier,
    )
    assert review.rejected_by_reason == ((SEMANTIC_REJECTED_HIDDEN_SOURCE_CLAIM, 1),)
    assert review.restatements_suppressed == 0
    assert review.verdicts == ()


def test_a_ruling_on_a_final_item_never_raises_the_gap_that_blocks_its_siblings() -> None:
    """R3: a ruling on an ``acknowledged_not_done`` item is set aside as a diagnostic only.

    Since unsupported rulings block every unruled open AI-powered finding on the check, counting
    it there would stall the siblings for no honesty gain. A ruling on an unknown target still
    counts as unsupported.
    """

    case = _dialogue_case()
    not_done = ResponseRecordedPayload(
        finding_id=fnd(2),
        finding_frontier=FRONTIER,
        disposition=ResponseDisposition.ACKNOWLEDGED_NOT_DONE,
        reason="The index is unreachable from this sandbox; out of scope here.",
    )
    final = replace(
        case,
        projection=replace(
            case.projection,
            responses={**case.projection.responses, fnd(2): record(not_done, 8)},
        ),
    )
    judgment = SemanticJudgment(
        "no_material_discrepancy",
        (),
        (_verdict(1, "fixed", str(res(2))), _verdict(2, "fixed", str(res(2)))),
    )
    review = validate_semantic_judgment(
        final, (), judgment, _provenance(), expected_frontier=final.frontier
    )
    assert _rulings(review) == [(str(fnd(1)), "fixed", (str(res(2)),))]
    assert (review.verdicts_unsupported, review.verdicts_set_aside) == (0, 1)

    unknown = validate_semantic_judgment(
        final,
        (),
        SemanticJudgment("no_material_discrepancy", (), (_verdict(9, "fixed", str(res(2))),)),
        _provenance(),
        expected_frontier=final.frontier,
    )
    assert (unknown.verdicts_unsupported, unknown.verdicts_set_aside) == (1, 0)


def test_a_narrower_challenge_is_its_own_item_not_a_restatement() -> None:
    """Greptile P1 on #943: a challenge about one subject of a broader recorded finding is a
    distinct issue (the receipt keys issues by their exact subject set). Suppressing it would
    lose its discrepancy and requested next step, which a ``still_present`` ruling cannot carry.
    """

    from builders.policy_cases import obligation_record
    from yoetz.domain.events import ObligationPublishedPayload, ObligationStatus

    obligations = {
        obl(number): obligation_record(
            ObligationPublishedPayload(
                obl(number), f"Obligation {number}", "criteria", ObligationStatus.OPEN
            ),
            2,
        )
        for number in (1, 2)
    }
    case = make_case(
        obligations=obligations,
        findings={
            fnd(1): finding_record(_recorded_semantic_finding(1, str(obl(1)), str(obl(2))), 5)
        },
    )
    narrower = validate_semantic_judgment(
        case,
        (),
        SemanticJudgment("challenges_returned", (_obligation_challenge(str(obl(1))),)),
        _provenance(),
        expected_frontier=case.frontier,
    )
    assert len(narrower.candidates) == 1
    assert narrower.candidates[0].subject_refs == (obl(1),)
    assert narrower.restatements_suppressed == 0
    assert narrower.verdicts == ()
    # The exact same subject set is still a restatement.
    same = validate_semantic_judgment(
        case,
        (),
        SemanticJudgment("challenges_returned", (_obligation_challenge(str(obl(1)), str(obl(2))),)),
        _provenance(),
        expected_frontier=case.frontier,
    )
    assert (len(same.candidates), same.restatements_suppressed) == (0, 1)


def test_a_challenge_replying_to_an_answered_finding_is_a_returned_linked_finding() -> None:
    """TB4 tb4f1 (issue #976): the reviewer's reply to an answer reaches the agent as a finding.

    A challenge that names the answered finding's id was folded into it as a ruling, leaving the
    agent with "findings returned: 0" and the concern only in summary text.
    """

    case = _restatement_case(obligation_recorded_at=2)
    answered = ResponseRecordedPayload(
        finding_id=fnd(1),
        finding_frontier=FRONTIER,
        disposition=ResponseDisposition.ACKNOWLEDGED,
        reason="The verification now runs in CI.",
    )
    answered_case = replace(
        case, projection=replace(case.projection, responses={fnd(1): record(answered, 6)})
    )
    reply = replace(
        _obligation_challenge(str(fnd(1))),
        discrepancy="The answer cites CI, but the recorded runs still fail two stencil cases.",
    )
    review = validate_semantic_judgment(
        answered_case,
        (),
        SemanticJudgment("challenges_returned", (reply,)),
        _provenance(),
        expected_frontier=answered_case.frontier,
    )
    assert len(review.candidates) == 1
    assert review.candidates[0].related_finding_ids == (fnd(1),)
    assert review.restatements_suppressed == 0

    # A re-raise that does not name the answered item, or of an unanswered one, is still folded.
    unnamed = validate_semantic_judgment(
        answered_case,
        (),
        SemanticJudgment("challenges_returned", (_obligation_challenge(str(obl(1))),)),
        _provenance(),
        expected_frontier=answered_case.frontier,
    )
    assert unnamed.candidates == ()
    assert unnamed.restatements_suppressed == 1
    unanswered = validate_semantic_judgment(
        case,
        (),
        SemanticJudgment("challenges_returned", (_obligation_challenge(str(fnd(1))),)),
        _provenance(),
        expected_frontier=case.frontier,
    )
    assert unanswered.candidates == ()
    assert unanswered.restatements_suppressed == 1


# --- Reviewer concerns are never discarded for an unsent citation (TB4 tb4v1, issue #976) -------
#
# The tb4v1 provider responses were not retained, so the regressions below rebuild the exact shape
# the run recorded (cited refs advertised but not sent, quotes read from JSON rows, a quote across
# Yoetz's redaction marker) with the task content replaced by neutral text.


def _json_row(statement: str) -> str:
    """A ledger row as the packet carries it: a JSON document with ASCII escapes."""

    return json.dumps({"event_id": str(evt(1)), "payload": {"statement": statement}})


def test_challenge_with_no_carried_ref_is_surfaced_not_silently_dropped() -> None:
    case = make_case(extra_refs=(clm(1), obl(1)))
    review = validate_semantic_judgment(
        case,
        (),
        SemanticJudgment(
            "challenges_returned",
            (_challenge(str(obl(1)), summary="Requested report is absent", snippet="report.json"),),
            review_summary="The requested report is absent.",
        ),
        _provenance(),
        expected_frontier=case.frontier,
        citable_refs=frozenset({str(clm(1)), str(obl(1))}),
        provider_input_text_by_ref={str(clm(1)): ("unrelated sent row",)},
    )

    assert review.candidates == ()
    assert review.rejected_by_reason == ((SEMANTIC_REJECTED_REF_NOT_CARRIED, 1),)
    # Not a quote problem: the snippet gap is not raised for a citation that was not sent.
    assert review.snippets_rejected == 0
    assert review.review_summary.startswith("The requested report is absent.")
    assert "Reviewer concerns not recorded as findings" in review.review_summary
    assert "Requested report is absent" in review.review_summary
    assert "Main agent: provide evidence for the claim." in review.review_summary
    # The unproven quote never travels with the surfaced concern.
    assert "report.json" not in review.review_summary


def test_uncited_invented_ref_is_still_outside_the_case() -> None:
    case = make_case(extra_refs=(clm(1),))
    review = validate_semantic_judgment(
        case,
        (),
        SemanticJudgment("challenges_returned", (_challenge(_INVENTED, snippet="x"),)),
        _provenance(),
        expected_frontier=case.frontier,
        citable_refs=frozenset({str(clm(1))}),
        provider_input_text_by_ref={str(clm(1)): ("x",)},
    )
    assert review.rejected_by_reason == ((SEMANTIC_REJECTED_REF_OUTSIDE_CASE, 1),)
    assert "Reviewer concerns not recorded" not in review.review_summary


def test_quote_matching_only_a_removed_ref_is_stripped_never_shown() -> None:
    case = make_case(extra_refs=(clm(1), clm(2)))
    review = validate_semantic_judgment(
        case,
        (),
        SemanticJudgment(
            "challenges_returned",
            (_challenge(str(clm(1)), str(clm(2)), snippet="text of the unsent row"),),
        ),
        _provenance(),
        expected_frontier=case.frontier,
        citable_refs=frozenset({str(clm(1)), str(clm(2))}),
        # Even if some text existed for clm(2) elsewhere, only sent rows of kept refs prove quotes.
        provider_input_text_by_ref={str(clm(1)): ("the sent row",)},
    )
    assert len(review.candidates) == 1
    challenge = review.candidates[0].challenge
    assert challenge is not None and challenge.snippet is None
    assert review.candidates[0].subject_refs == (clm(1),)
    assert review.refs_reduced == 1
    assert review.snippets_rejected == 1


def test_tb4v1_atrx_routine_review_mints_both_concerns() -> None:
    """atrx item 45: two challenges, both dropped as ``snippet_invalid``, zero findings minted.

    The first cited the sent claim plus evidence whose row was omitted (``not_selected``) and quoted
    the claim with a typographic apostrophe the JSON row carries as an escape; the second cited the
    report obligation together with this check's local finding about the missing report.
    """

    local = Finding(
        finding_id=fnd(9),
        kind=FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED,
        origin=FindingOrigin.DETERMINISTIC,
        priority=2,
        summary="A requested output file does not exist in the workspace at check time.",
        detail="Write the requested output.",
        subject_refs=(obl(1),),
        policy_id="work-integrity",
        policy_version="0.3.0",
        subject_frontier=FRONTIER,
        coverage=BASE_COVERAGE,
    )
    case = make_case(extra_refs=(clm(1), clm(2), obl(1)))
    claim_row = _json_row("The report\u2019s annotations\ncame from a custom model.")
    judgment = SemanticJudgment(
        "challenges_returned",
        (
            _challenge(
                str(clm(1)),
                str(clm(2)),
                summary="Annotations are not from the requested model",
                snippet="The report's annotations came from a custom model.",
            ),
            _challenge(
                str(fnd(9)),
                str(obl(1)),
                summary="Requested report is absent",
                snippet="requested item never attempted",
            ),
        ),
        review_summary="[redacted summary of the routine review]",
    )
    review = validate_semantic_judgment(
        case,
        (local,),
        judgment,
        _provenance(),
        expected_frontier=case.frontier,
        citable_refs=frozenset({str(clm(1)), str(clm(2)), str(obl(1)), str(fnd(9))}),
        # The local finding reached the reviewer as its assessment row, which the disclosure
        # indexes as sent text for the finding.
        provider_input_text_by_ref={
            str(clm(1)): (claim_row,),
            str(fnd(9)): (
                json.dumps({"finding_kind": "requested_item_never_attempted", "finding_ref": "x"}),
            ),
        },
    )

    assert review.challenges_rejected == 0
    assert [candidate.summary for candidate in review.candidates] == [
        "Annotations are not from the requested model",
        "Requested report is absent",
    ]
    first, second = (candidate.challenge for candidate in review.candidates)
    assert first is not None and second is not None
    # The recorded quote is the verbatim sent text, not the reviewer's spelling of it.
    assert first.snippet == "The report\u2019s annotations\ncame from a custom model."
    # The reviewer paraphrased the assessment row's kind: not proven, so removed and disclosed.
    assert second.snippet is None
    assert review.candidates[1].subject_refs == (obl(1),)
    assert review.refs_reduced == 2
    assert review.snippets_rejected == 1


def test_tb4v1_data_anon_quote_across_the_redaction_marker_is_proven() -> None:
    """data-anon item 108: the reviewer quoted a line around Yoetz's own redaction marker."""

    case = make_case(extra_refs=(clm(1),))
    sent = "token = [REDACTED] + ':' + subject_id"
    review = validate_semantic_judgment(
        case,
        (),
        SemanticJudgment(
            "challenges_returned",
            (_challenge(str(clm(1)), snippet="token = [redacted] + ':' + subject_id"),),
        ),
        _provenance(),
        expected_frontier=case.frontier,
        citable_refs=frozenset({str(clm(1))}),
        provider_input_text_by_ref={str(clm(1)): (sent,)},
    )
    assert len(review.candidates) == 1
    challenge = review.candidates[0].challenge
    assert challenge is not None and challenge.snippet == sent
    assert review.snippets_rejected == 0


def test_tb4v1_heat_pump_lone_unsent_citation_keeps_the_concern_visible() -> None:
    """heat-pump item 47: a lone challenge cited only refs whose rows were omitted."""

    case = make_case(extra_refs=(clm(1), clm(2)))
    review = validate_semantic_judgment(
        case,
        (),
        SemanticJudgment(
            "challenges_returned",
            (_challenge(str(clm(2)), summary="Decision count not reconciled", snippet="20"),),
            review_summary="[redacted summary of the review]",
        ),
        _provenance(),
        expected_frontier=case.frontier,
        citable_refs=frozenset({str(clm(1)), str(clm(2))}),
        provider_input_text_by_ref={str(clm(1)): ("sent row",)},
    )
    assert review.challenges_returned == 1
    assert review.rejected_by_reason == ((SEMANTIC_REJECTED_REF_NOT_CARRIED, 1),)
    assert "Decision count not reconciled" in review.review_summary
    assert review.snippets_rejected == 0


def test_surfaced_concerns_respect_the_review_text_bound() -> None:
    case = make_case(extra_refs=(clm(1), clm(2), clm(3), clm(4)))
    long = "x" * 1000
    review = validate_semantic_judgment(
        case,
        (),
        SemanticJudgment(
            "challenges_returned",
            tuple(
                ReviewerChallenge(
                    FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
                    long,
                    (str(clm(number)),),
                    "d",
                    "a",
                    "\u00e9" * 500,
                    "provide_evidence",
                    "u",
                )
                for number in (2, 3, 4)
            ),
            review_summary="y" * 1000,
        ),
        _provenance(),
        expected_frontier=case.frontier,
        citable_refs=frozenset(str(clm(number)) for number in (1, 2, 3, 4)),
        provider_input_text_by_ref={str(clm(1)): ("sent",)},
    )
    encoded = review.review_summary.encode("utf-8")
    assert len(encoded) <= 4096
    assert review.review_summary.endswith("[truncated]")
    # The cut lands inside multi-byte text and never leaves a replacement character.
    assert "\ufffd" not in review.review_summary
    assert review.challenges_rejected == 3


def test_mixed_fence_outcomes_reconcile() -> None:
    """Reduced, unanchored and outside challenges in one review all add up."""

    case = make_case(extra_refs=(clm(1), clm(2)))
    review = validate_semantic_judgment(
        case,
        (),
        SemanticJudgment(
            "challenges_returned",
            (
                _challenge(str(clm(1)), str(clm(2)), summary="Reduced", snippet="sent"),
                _challenge(str(clm(2)), summary="Unanchored"),
                _challenge(_INVENTED, summary="Outside"),
            ),
        ),
        _provenance(),
        expected_frontier=case.frontier,
        citable_refs=frozenset({str(clm(1)), str(clm(2))}),
        provider_input_text_by_ref={str(clm(1)): ("sent",)},
    )
    assert review.challenges_returned == 3
    assert [candidate.summary for candidate in review.candidates] == ["Reduced"]
    assert review.challenges_returned == (
        len(review.candidates) + review.challenges_rejected + review.restatements_suppressed
    )
    assert dict(review.rejected_by_reason) == {
        SEMANTIC_REJECTED_REF_NOT_CARRIED: 1,
        SEMANTIC_REJECTED_REF_OUTSIDE_CASE: 1,
    }
    assert review.refs_reduced == 1
    assert review.snippets_rejected == 0
    assert "Unanchored" in review.review_summary
    assert "Outside" not in review.review_summary


# --- Re-raises named by ``restates`` link to the earlier finding (issue #980, TB4 tb4n1 D5) ----


def _cargo_case(
    *,
    resolved: bool = False,
    disposition: ResponseDisposition = ResponseDisposition.REJECTED,
) -> DeterministicCase:
    """cargo-flight-dispatch shape: one concern raised at 5, answered at 6, then new work.

    The reviewer re-raised "the dispatchable single-tour plan is not delivered" on 7 closing
    checks, each time citing the agent's newest result, and each re-raise was minted under a new
    id beside the still-open original.
    """

    from builders.policy_cases import obligation_record
    from yoetz.domain.events import ObligationPublishedPayload, ObligationStatus

    obligation = obligation_record(
        ObligationPublishedPayload(
            obl(1), "Deliver the dispatch plan", "one dispatchable tour", ObligationStatus.OPEN
        ),
        2,
    )
    results = {
        res(number): record(
            ResultRecordedPayload(
                res(number), act(number), ResultOutcome.SUCCESS, summary=f"attempt {number}"
            ),
            6 + number,
        )
        for number in range(1, 8)
    }
    from yoetz.domain.findings import FINDING_KIND_TRAITS, finding_policy_identity

    rejected = ResponseRecordedPayload(
        finding_id=fnd(1),
        finding_frontier=FRONTIER,
        disposition=disposition,
        reason="No single tour satisfies the MTOW limit, so the plan cannot be delivered.",
    )
    kind = FindingKind.TASK_REQUIREMENT_UNMET
    policy_id, policy_version = finding_policy_identity(kind)
    return make_case(
        obligations={obl(1): obligation},
        results=results,
        findings={
            fnd(1): finding_record(
                replace(
                    _recorded_semantic_finding(1, str(obl(1))),
                    kind=kind,
                    priority=FINDING_KIND_TRAITS[kind][0],
                    policy_id=policy_id,
                    policy_version=policy_version,
                    summary="The required dispatchable single-tour plan is not delivered.",
                ),
                5,
                resolved_by_check_event_id=evt(8) if resolved else None,
            )
        },
        responses={fnd(1): record(rejected, 6)},
    )


def _re_raise(number: int, *, restates: str | None) -> ReviewerChallenge:
    return replace(
        _challenge(str(res(number)), summary="The dispatchable single-tour plan is not delivered"),
        finding_kind=FindingKind.TASK_REQUIREMENT_UNMET,
        requested_next_step="act",
        restates=restates,
    )


def test_cargo_re_raises_named_by_restates_stay_one_open_finding() -> None:
    """Seven closing checks re-raising one concern record seven rounds on one item, not 7 ids."""

    case = _cargo_case()
    for number in range(1, 8):
        review = validate_semantic_judgment(
            case,
            (),
            SemanticJudgment("challenges_returned", (_re_raise(number, restates=str(fnd(1))),)),
            _provenance(),
            expected_frontier=case.frontier,
            prior_finding_refs=frozenset({str(fnd(1))}),
        )
        assert review.candidates == ()
        assert review.restatements_suppressed == 1
        # The agent answered (rejected), so the ruling is the reviewer's verdict on that answer;
        # it advances the item's review round, so the per-finding budget counts this concern.
        rulings = _rulings(review)
        assert [(ref, verdict) for ref, verdict, _cited in rulings] == [
            (str(fnd(1)), "answered_not_fixed")
        ]
        assert rulings[0][2]  # cites what the re-raise cited
        assert f"- {fnd(1)}: The dispatchable single-tour plan is not delivered" in (
            review.review_summary
        )
        assert "Reviewer re-raised earlier findings" in review.review_summary


def test_restates_of_another_concern_mints_a_linked_finding_and_never_rules_on_the_target() -> None:
    """Adversarial review of #980: a ``code_defect`` naming a ``task_requirement_unmet`` finding
    is a different concern. Folding it would turn a new defect into 0 findings and a suppression;
    it is minted, linked to the named finding, and no ruling is recorded on the named finding."""

    case = _cargo_case()
    challenge = replace(
        _re_raise(1, restates=str(fnd(1))),
        finding_kind=FindingKind.CODE_DEFECT,
        summary="The tour planner divides by zero on an empty manifest",
    )
    review = validate_semantic_judgment(
        case,
        (),
        SemanticJudgment("challenges_returned", (challenge,)),
        _provenance(),
        expected_frontier=case.frontier,
        prior_finding_refs=frozenset({str(fnd(1))}),
    )
    assert len(review.candidates) == 1
    assert review.candidates[0].kind is FindingKind.CODE_DEFECT
    assert review.candidates[0].related_finding_ids == (fnd(1),)
    assert review.restatements_suppressed == 0
    # Round-3 review: a different concern only links; it never rules on the named item, so the
    # reviewer's own ruling on that item in the same response stands.
    assert _rulings(review) == []
    assert review.refs_reduced == 0


def test_restates_outside_the_packet_prior_findings_links_without_a_reduction() -> None:
    """A ``restates`` the packet did not carry as rulable is not a ref the challenge rests on:
    the challenge is minted linked to the named finding, and nothing counts toward
    ``semantic_review_refs_reduced`` (which would keep the task from closing). An id outside the
    fence is dropped: the challenge stands on its own."""

    case = _cargo_case()
    review = validate_semantic_judgment(
        case,
        (),
        SemanticJudgment("challenges_returned", (_re_raise(1, restates=str(fnd(1))),)),
        _provenance(),
        expected_frontier=case.frontier,
        prior_finding_refs=frozenset(),  # the packet did not carry it
    )
    assert len(review.candidates) == 1
    assert review.candidates[0].related_finding_ids == (fnd(1),)
    assert review.restatements_suppressed == 0
    assert review.refs_reduced == 0
    unknown = validate_semantic_judgment(
        case,
        (),
        SemanticJudgment("challenges_returned", (_re_raise(1, restates=str(fnd(9))),)),
        _provenance(),
        expected_frontier=case.frontier,
    )
    assert len(unknown.candidates) == 1 and unknown.refs_reduced == 0
    assert unknown.candidates[0].related_finding_ids == ()


def test_restates_of_a_resolved_finding_mints_a_linked_successor() -> None:
    """Done stays done: a re-raise after verified resolution is a #458 successor, linked to the
    resolved finding it names, and the naming is never counted as a reduced ref."""

    case = _cargo_case(resolved=True)
    review = validate_semantic_judgment(
        case,
        (),
        SemanticJudgment("challenges_returned", (_re_raise(1, restates=str(fnd(1))),)),
        _provenance(),
        expected_frontier=case.frontier,
    )
    assert len(review.candidates) == 1
    assert review.candidates[0].related_finding_ids == (fnd(1),)
    assert review.restatements_suppressed == 0
    assert review.verdicts == ()
    assert review.refs_reduced == 0


def test_a_re_raise_of_an_acknowledged_finding_is_recorded_on_it_not_minted() -> None:
    """Adversarial review of #980 (cargo 5, pretrain 11): the agent gave up
    (``acknowledged_not_done``), the packet carried the item as a nameable settled row, and the
    reviewer re-raised the same concern. It is recorded on that item as a ruling the reducer
    folds into ``settled_reraise_count`` (the standing premise dispute), never a new id. Not
    carried, or another kind: a new finding linked to it."""

    case = _cargo_case(disposition=ResponseDisposition.ACKNOWLEDGED_NOT_DONE)
    for number in range(1, 4):
        review = validate_semantic_judgment(
            case,
            (),
            SemanticJudgment("challenges_returned", (_re_raise(number, restates=str(fnd(1))),)),
            _provenance(),
            expected_frontier=case.frontier,
            prior_finding_refs=frozenset(),
            settled_finding_refs=frozenset({str(fnd(1))}),
        )
        assert review.candidates == ()
        assert review.restatements_suppressed == 1
        assert [(ref, verdict) for ref, verdict, _cited in _rulings(review)] == [
            (str(fnd(1)), "still_present")
        ]
        assert f"- {fnd(1)}: The dispatchable single-tour plan is not delivered" in (
            review.review_summary
        )
        assert review.refs_reduced == 0
    other = replace(_re_raise(1, restates=str(fnd(1))), finding_kind=FindingKind.CODE_DEFECT)
    for settled, challenge in (
        (frozenset[str](), _re_raise(1, restates=str(fnd(1)))),
        (
            frozenset({str(fnd(1))}),
            other,
        ),
    ):
        minted = validate_semantic_judgment(
            case,
            (),
            SemanticJudgment("challenges_returned", (challenge,)),
            _provenance(),
            expected_frontier=case.frontier,
            prior_finding_refs=frozenset(),
            settled_finding_refs=settled,
        )
        assert len(minted.candidates) == 1
        assert minted.candidates[0].related_finding_ids == (fnd(1),)
        assert minted.verdicts == () and minted.refs_reduced == 0


# --- Disagreement after a reasoned rebuttal (issue #1020, ADR-040, TB4 tb4n2 R1) ----------------
#
# formal-crypto S (tb4n2): the reviewer raised ``task_requirement_unmet`` ("short known samples
# cannot reconstruct longer targets"), the agent rejected it with a reasoned rebuttal, and three
# closing reviews repeated it citing nothing newer than that rejection. The agent then emptied a
# working solver. A held-open ruling over a reasoned rejection with no newer cited material is
# now recorded as ``disputed_after_rebuttal``: final, non-blocking, disclosed.


def _formal_crypto_case(
    *, reason: str | None = "Sixteen known blocks suffice under fixed benchmark parameters."
) -> DeterministicCase:
    from builders.policy_cases import claim_record, obligation_record
    from yoetz.domain.events import (
        ClaimKind,
        ClaimRecordedPayload,
        ObligationPublishedPayload,
        ObligationStatus,
    )
    from yoetz.domain.findings import FINDING_KIND_TRAITS, finding_policy_identity

    kind = FindingKind.TASK_REQUIREMENT_UNMET
    policy_id, policy_version = finding_policy_identity(kind)
    finding = replace(
        _recorded_semantic_finding(1, str(clm(1)), str(obl(1))),
        kind=kind,
        priority=FINDING_KIND_TRAITS[kind][0],
        policy_id=policy_id,
        policy_version=policy_version,
        summary="Short known samples cannot reconstruct longer targets.",
    )
    disposition = (
        ResponseDisposition.REJECTED if reason is not None else ResponseDisposition.ACKNOWLEDGED
    )
    rebuttal = ResponseRecordedPayload(
        finding_id=fnd(1),
        finding_frontier=FRONTIER,
        disposition=disposition,
        reason=reason,
    )
    return make_case(
        obligations={
            obl(1): obligation_record(
                ObligationPublishedPayload(
                    obl(1), "Write solve.sage", "solver passes", ObligationStatus.OPEN
                ),
                2,
            )
        },
        claims={
            clm(1): claim_record(
                ClaimRecordedPayload(clm(1), ClaimKind.COMPLETION, "solve.sage works", ()), 4
            )
        },
        results={
            res(1): record(
                ResultRecordedPayload(res(1), act(1), ResultOutcome.SUCCESS, summary="old"), 3
            ),
            res(2): record(
                ResultRecordedPayload(res(2), act(2), ResultOutcome.FAILURE, summary="new"), 12
            ),
        },
        findings={fnd(1): finding_record(finding, 5)},
        responses={fnd(1): record(rebuttal, 8)},
    )


def _formal_crypto_review(
    judgment: SemanticJudgment, case: DeterministicCase | None = None
) -> SemanticJudgmentReview:
    current = _formal_crypto_case() if case is None else case
    return validate_semantic_judgment(
        current,
        (),
        judgment,
        _provenance(),
        expected_frontier=current.frontier,
        prior_finding_refs=frozenset({str(fnd(1))}),
    )


@pytest.mark.parametrize("ruling", ["still_present", "answered_not_fixed", "unassessable"])
def test_formal_crypto_held_open_ruling_over_a_rebuttal_is_a_standing_disagreement(
    ruling: str,
) -> None:
    review = _formal_crypto_review(
        SemanticJudgment(
            "no_material_discrepancy", (), (_verdict(1, ruling, str(clm(1)), str(res(1))),)
        )
    )
    assert [(ref, verdict) for ref, verdict, _cited in _rulings(review)] == [
        (str(fnd(1)), "disputed_after_rebuttal")
    ]
    assert review.verdicts_unsupported == 0


def test_a_cite_free_still_present_over_a_rebuttal_is_disputed_not_unassessable() -> None:
    review = _formal_crypto_review(
        SemanticJudgment("no_material_discrepancy", (), (_verdict(1, "still_present"),))
    )
    assert _rulings(review) == [(str(fnd(1)), "disputed_after_rebuttal", ())]


def test_material_newer_than_the_rebuttal_keeps_the_reviewers_ruling() -> None:
    review = _formal_crypto_review(
        SemanticJudgment(
            "no_material_discrepancy", (), (_verdict(1, "still_present", str(res(2))),)
        )
    )
    assert _rulings(review) == [(str(fnd(1)), "still_present", (str(res(2)),))]


def test_no_reasoned_rejection_means_no_dispute() -> None:
    acknowledged = _formal_crypto_case(reason=None)
    review = _formal_crypto_review(
        SemanticJudgment(
            "no_material_discrepancy", (), (_verdict(1, "still_present", str(clm(1))),)
        ),
        acknowledged,
    )
    assert _rulings(review) == [(str(fnd(1)), "still_present", (str(clm(1)),))]


def test_a_ruling_on_an_unshown_rejected_finding_stays_unassessable() -> None:
    case = _formal_crypto_case()
    review = validate_semantic_judgment(
        case,
        (),
        SemanticJudgment(
            "no_material_discrepancy", (), (_verdict(1, "still_present", str(clm(1))),)
        ),
        _provenance(),
        expected_frontier=case.frontier,
        prior_finding_refs=frozenset(),  # the reviewer never saw the rebuttal
    )
    assert [(ref, verdict) for ref, verdict, _cited in _rulings(review)] == [
        (str(fnd(1)), "unassessable")
    ]


def _formal_crypto_reraise(*refs: str, restates: str | None = None) -> ReviewerChallenge:
    return replace(
        _challenge(*refs, summary="Short known samples cannot reconstruct longer targets"),
        finding_kind=FindingKind.TASK_REQUIREMENT_UNMET,
        requested_next_step="act",
        restates=restates,
    )


def test_formal_crypto_re_raises_without_newer_material_fold_into_the_dispute() -> None:
    """The same concern raised again (named, unnamed, or replying to the rejection) folds."""

    for challenge in (
        _formal_crypto_reraise(str(clm(1)), str(obl(1)), restates=str(fnd(1))),
        _formal_crypto_reraise(str(clm(1)), str(obl(1))),
        _formal_crypto_reraise(str(fnd(1))),
    ):
        review = _formal_crypto_review(SemanticJudgment("challenges_returned", (challenge,)))
        assert review.candidates == ()
        assert review.restatements_suppressed == 1
        assert [(ref, verdict) for ref, verdict, _cited in _rulings(review)] == [
            (str(fnd(1)), "disputed_after_rebuttal")
        ]


def test_a_re_raise_with_material_newer_than_the_rebuttal_is_still_raised() -> None:
    review = _formal_crypto_review(
        SemanticJudgment(
            "challenges_returned",
            (_formal_crypto_reraise(str(clm(1)), str(obl(1)), str(res(2)), restates=str(fnd(1))),),
        )
    )
    # Named restatement with newer material: recorded on the item as the reviewer's ruling.
    assert [(ref, verdict) for ref, verdict, _cited in _rulings(review)] == [
        (str(fnd(1)), "answered_not_fixed")
    ]


def _disputed_case() -> DeterministicCase:
    base = _formal_crypto_case()
    disputed = replace(
        base.projection.findings[fnd(1)], disputed_after_rebuttal_by_check_event_id=evt(9)
    )
    return replace(
        base,
        projection=replace(base.projection, findings={fnd(1): disputed}),
    )


def test_a_disputed_finding_is_final_and_its_restatement_is_folded_without_a_ruling() -> None:
    case = _disputed_case()
    rulings = _formal_crypto_review(
        SemanticJudgment(
            "no_material_discrepancy", (), (_verdict(1, "still_present", str(clm(1))),)
        ),
        case,
    )
    assert rulings.verdicts == ()
    assert rulings.verdicts_set_aside == 1
    for challenge in (
        _formal_crypto_reraise(str(clm(1)), str(obl(1)), restates=str(fnd(1))),
        _formal_crypto_reraise(str(clm(1)), str(obl(1))),
    ):
        review = _formal_crypto_review(SemanticJudgment("challenges_returned", (challenge,)), case)
        assert review.candidates == ()
        assert review.restatements_suppressed == 1
        assert review.verdicts == ()
    # Newer material than the rebuttal is a new sighting: minted, linked to the dispute.
    newer = _formal_crypto_review(
        SemanticJudgment(
            "challenges_returned",
            (_formal_crypto_reraise(str(obl(1)), str(res(2)), restates=str(fnd(1))),),
        ),
        case,
    )
    assert len(newer.candidates) == 1
    assert newer.candidates[0].related_finding_ids == (fnd(1),)


# --- Restatement folding across claim churn (issue #1020, tb4n2 payments P1-10) -----------------


def test_payments_claim_churn_folds_one_concern_into_one_finding() -> None:
    """payments S (tb4n2) minted four ids for one concern: each re-published completion claim
    changed the subject set. The same kind over the same obligation is one concern."""

    from builders.policy_cases import claim_record, obligation_record
    from yoetz.domain.events import (
        ClaimKind,
        ClaimRecordedPayload,
        ObligationPublishedPayload,
        ObligationStatus,
    )
    from yoetz.domain.findings import FINDING_KIND_TRAITS, finding_policy_identity

    kind = FindingKind.TASK_REQUIREMENT_UNMET
    policy_id, policy_version = finding_policy_identity(kind)
    earlier = replace(
        _recorded_semantic_finding(1, str(clm(1)), str(evt(30)), str(obl(1))),
        kind=kind,
        priority=FINDING_KIND_TRAITS[kind][0],
        policy_id=policy_id,
        policy_version=policy_version,
        summary="Actual-pipeline notification correctness remains unverified",
    )
    claims = {
        clm(1): claim_record(
            ClaimRecordedPayload(clm(1), ClaimKind.COMPLETION, "done", ()),
            4,
            superseded_by_claim_id=clm(2),
        ),
        clm(2): claim_record(ClaimRecordedPayload(clm(2), ClaimKind.COMPLETION, "done", ()), 11),
    }
    case = make_case(
        obligations={
            obl(1): obligation_record(
                ObligationPublishedPayload(
                    obl(1), "Correct notifications", "receiver deduplicates", ObligationStatus.OPEN
                ),
                3,
            )
        },
        claims=claims,
        findings={fnd(1): finding_record(earlier, 5)},
        extra_refs=(evt(30),),
    )
    churned = replace(
        _challenge(str(clm(2)), str(obl(1)), summary="Notification correctness remains unmet"),
        finding_kind=kind,
    )
    review = validate_semantic_judgment(
        case,
        (),
        SemanticJudgment("challenges_returned", (churned,)),
        _provenance(),
        expected_frontier=case.frontier,
    )
    assert review.candidates == ()
    assert review.restatements_suppressed == 1
    assert [(ref, verdict) for ref, verdict, _cited in _rulings(review)] == [
        (str(fnd(1)), "still_present")
    ]
    # Another kind on the same obligation is a different concern.
    other = validate_semantic_judgment(
        case,
        (),
        SemanticJudgment(
            "challenges_returned", (replace(churned, finding_kind=FindingKind.CODE_DEFECT),)
        ),
        _provenance(),
        expected_frontier=case.frontier,
    )
    assert len(other.candidates) == 1


# --- No AI-powered "never attempted" before any completion claim (issue #1020, tb4n2 P1-7) ------


def test_pre_work_never_attempted_challenges_are_dropped_until_work_is_claimed() -> None:
    from builders.policy_cases import claim_record
    from yoetz.application.check import SEMANTIC_REJECTED_ROUTINE_COMPLETENESS
    from yoetz.domain.events import ClaimKind, ClaimRecordedPayload

    never = replace(
        _challenge(str(obl(1)), summary="Requested solver never attempted"),
        finding_kind=FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED,
        requested_next_step="act",
    )
    pre_work = make_case(extra_refs=(obl(1),))
    review = validate_semantic_judgment(
        pre_work,
        (),
        SemanticJudgment("challenges_returned", (never,)),
        _provenance(),
        expected_frontier=pre_work.frontier,
    )
    assert review.candidates == ()
    assert review.rejected_by_reason == ((SEMANTIC_REJECTED_ROUTINE_COMPLETENESS, 1),)

    claimed = make_case(
        claims={
            clm(1): claim_record(
                ClaimRecordedPayload(clm(1), ClaimKind.COMPLETION, "all done", ()), 4
            )
        },
        extra_refs=(obl(1),),
    )
    after = validate_semantic_judgment(
        claimed,
        (),
        SemanticJudgment("challenges_returned", (never,)),
        _provenance(),
        expected_frontier=claimed.frontier,
    )
    assert len(after.candidates) == 1


def test_a_reply_citing_material_between_the_finding_and_the_rebuttal_folds_into_the_dispute() -> (
    None
):
    """Codex review round 1: material recorded before the rejection is what the agent answered.

    Finding at 5, a result at 6, the reasoned rejection at 8: a reply naming the finding and
    citing that result brings nothing newer than the rebuttal, so it folds as the dispute.
    """

    base = _formal_crypto_case()
    middle = record(ResultRecordedPayload(res(3), act(3), ResultOutcome.SUCCESS, summary="mid"), 6)
    case = replace(
        base,
        projection=replace(base.projection, results={**base.projection.results, res(3): middle}),
        allowed_ids=base.allowed_ids | {res(3), evt(6)},
        coverage_by_ref={**base.coverage_by_ref, res(3): BASE_COVERAGE, evt(6): BASE_COVERAGE},
    )
    review = _formal_crypto_review(
        SemanticJudgment(
            "challenges_returned", (_formal_crypto_reraise(str(fnd(1)), str(res(3))),)
        ),
        case,
    )
    assert review.candidates == ()
    assert [(ref, verdict) for ref, verdict, _cited in _rulings(review)] == [
        (str(fnd(1)), "disputed_after_rebuttal")
    ]
    named = _formal_crypto_review(
        SemanticJudgment(
            "challenges_returned",
            (_formal_crypto_reraise(str(clm(1)), str(obl(1)), restates=str(fnd(1))),),
        ),
        case,
    )
    # A final dispute never tells the agent to answer it.
    assert "citing nothing newer" in named.review_summary
    assert "answer it there" not in named.review_summary


def test_a_newer_restatement_outranks_a_stale_ruling_in_the_same_review() -> None:
    """Codex review round 1: a stale still_present and a named restatement citing a failure
    recorded after the rebuttal; the newer sighting keeps the item open."""

    review = _formal_crypto_review(
        SemanticJudgment(
            "challenges_returned",
            (_formal_crypto_reraise(str(clm(1)), str(obl(1)), str(res(2)), restates=str(fnd(1))),),
            (_verdict(1, "still_present", str(clm(1))),),
        )
    )
    assert [(ref, verdict) for ref, verdict, _cited in _rulings(review)] == [
        (str(fnd(1)), "answered_not_fixed")
    ]
    assert "answer it there" in review.review_summary


def test_citing_the_event_of_a_republished_claim_is_not_new_material() -> None:
    """Codex review round 2: a claim's own event id is the claim, not new evidence."""

    from builders.policy_cases import claim_record
    from yoetz.domain.events import ClaimKind, ClaimRecordedPayload

    base = _formal_crypto_case()
    republished = claim_record(
        ClaimRecordedPayload(clm(2), ClaimKind.COMPLETION, "solve.sage works", ()), 11
    )
    case = replace(
        base,
        projection=replace(base.projection, claims={**base.projection.claims, clm(2): republished}),
        allowed_ids=base.allowed_ids | {clm(2), evt(11)},
        coverage_by_ref={**base.coverage_by_ref, clm(2): BASE_COVERAGE, evt(11): BASE_COVERAGE},
    )
    review = _formal_crypto_review(
        SemanticJudgment(
            "no_material_discrepancy", (), (_verdict(1, "still_present", str(evt(11))),)
        ),
        case,
    )
    assert [(ref, verdict) for ref, verdict, _cited in _rulings(review)] == [
        (str(fnd(1)), "disputed_after_rebuttal")
    ]


def test_a_withdrawn_contradicted_by_a_stale_restatement_is_the_dispute() -> None:
    """Codex review round 2: contradictory output never restores pressure on a rebutted item."""

    review = _formal_crypto_review(
        SemanticJudgment(
            "challenges_returned",
            (_formal_crypto_reraise(str(clm(1)), str(obl(1)), restates=str(fnd(1))),),
            (_verdict(1, "withdrawn"),),
        )
    )
    assert [(ref, verdict) for ref, verdict, _cited in _rulings(review)] == [
        (str(fnd(1)), "disputed_after_rebuttal")
    ]
    assert "answer it there" not in review.review_summary


def _with_republished_claim(case: DeterministicCase) -> DeterministicCase:
    from builders.policy_cases import claim_record
    from yoetz.domain.events import ClaimKind, ClaimRecordedPayload

    republished = claim_record(
        ClaimRecordedPayload(clm(2), ClaimKind.COMPLETION, "solve.sage works", ()), 11
    )
    return replace(
        case,
        projection=replace(case.projection, claims={**case.projection.claims, clm(2): republished}),
        allowed_ids=case.allowed_ids | {clm(2), evt(11)},
        coverage_by_ref={**case.coverage_by_ref, clm(2): BASE_COVERAGE, evt(11): BASE_COVERAGE},
    )


def test_an_unnamed_repeat_citing_a_republished_claim_event_folds_into_the_dispute() -> None:
    """Codex review round 3: the new claim and its event are bookkeeping, not new material."""

    case = _with_republished_claim(_formal_crypto_case())
    review = _formal_crypto_review(
        SemanticJudgment(
            "challenges_returned",
            (_formal_crypto_reraise(str(clm(2)), str(evt(11)), str(obl(1))),),
        ),
        case,
    )
    assert review.candidates == ()
    assert [(ref, verdict) for ref, verdict, _cited in _rulings(review)] == [
        (str(fnd(1)), "disputed_after_rebuttal")
    ]


def test_an_unsupported_fixed_with_a_stale_restatement_is_the_dispute() -> None:
    """Codex review round 3: a reduced ``fixed`` never restores pressure on a rebutted item."""

    review = _formal_crypto_review(
        SemanticJudgment(
            "challenges_returned",
            (_formal_crypto_reraise(str(clm(1)), str(obl(1)), restates=str(fnd(1))),),
            (_verdict(1, "fixed"),),
        )
    )
    assert [(ref, verdict) for ref, verdict, _cited in _rulings(review)] == [
        (str(fnd(1)), "disputed_after_rebuttal")
    ]
    assert "answer it there" not in review.review_summary


def test_a_historical_obligation_publication_event_is_not_new_material() -> None:
    """Codex review round 3: an obligation event the projection no longer holds is still
    bookkeeping when the frozen history names it."""

    from yoetz.kernel.deterministic_checks import FrozenHistoryEvent

    base = _formal_crypto_case()
    historical = FrozenHistoryEvent(
        event_id=evt(10),
        schema_name="obligation_published",
        schema_version="1.1.0",
        ingestion_sequence=10,
        occurred_at="2026-10-08T12:00:00.000Z",
        accepted_at=None,
        occurred_at_consistency=None,
        payload_digest="sha256:" + "c" * 64,
        content_visibility="not_recorded",
        payload=None,
    )
    case = replace(
        base,
        history=(historical,),
        history_availability="available",
        allowed_ids=base.allowed_ids | {evt(10)},
        coverage_by_ref={**base.coverage_by_ref, evt(10): BASE_COVERAGE},
    )
    review = _formal_crypto_review(
        SemanticJudgment(
            "no_material_discrepancy", (), (_verdict(1, "still_present", str(evt(10))),)
        ),
        case,
    )
    assert [(ref, verdict) for ref, verdict, _cited in _rulings(review)] == [
        (str(fnd(1)), "disputed_after_rebuttal")
    ]
