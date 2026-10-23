"""#1205: admitted repair rulings survive optional quote loss; eligibility stays prefix-bound."""

# pyright: reportPrivateUsage=false

from collections.abc import Iterator
from dataclasses import replace

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from builders.policy_cases import fnd, obl, res
from finishup.application.check import _review_fence_gaps, validate_semantic_judgment
from finishup.domain.events import EventSchema, ResultOutcome
from finishup.domain.findings import SELF_VERIFIED_GUIDANCE, FindingOrigin
from finishup.kernel.finding_resolution import (
    finding_is_resolved,
    finding_resolution_attempt,
    finding_resolution_explanation,
    issue_key,
    resolution_blockers,
)
from finishup.kernel.projections import projection_from_snapshot, projection_snapshot
from finishup.kernel.reducers import replay
from finishup.kernel.self_verification import (
    self_verification_evaluation,
    self_verification_refusal,
)
from finishup.kernel.task_facts import register_command_identity_key
from finishup.ports.semantic import SemanticJudgment, VerifiedReviewItem
from finishup.protocol.coverage import LedgerFreshness
from unit.application import test_semantic_post_validation as post
from unit.kernel import test_finding_resolution as fr
from unit.kernel import test_intelligent_freshness as freshness

_QUOTE = "semantic_review_snippet_invalid"


@pytest.fixture
def command_key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


@pytest.mark.parametrize("bad_quote", [False, True])
@pytest.mark.parametrize("ruling", ["fixed", "silence", "unsupported", "unsent", "reraised"])
def test_production_admission_fence_and_qualification_with_optional_bad_quote(
    bad_quote: bool, ruling: str
) -> None:
    case = post._dialogue_case()
    finding = case.projection.findings[fnd(1)].payload
    assert finding is not None
    index = {
        str(fnd(1)): ("recorded prior finding",),
        str(res(1)): ("result before the finding",),
        str(res(2)): ("regression repaired",),
        str(obl(2)): ("unrelated sibling material",),
    }
    if ruling == "unsent":
        del index[str(res(2))]
    challenges = (
        (post._challenge(str(fnd(1)), str(obl(2)), snippet="invented quote"),)
        if ruling == "reraised"
        else ()
    )
    judgment = SemanticJudgment(
        "challenges_returned" if challenges else "no_material_discrepancy",
        challenges,
        ()
        if ruling == "silence"
        else (post._verdict(1, "fixed", str(res(1) if ruling == "unsupported" else res(2))),),
        verified=(
            (VerifiedReviewItem("Sibling note", "supported", (str(obl(2)),), "invented quote"),)
            if bad_quote
            else ()
        ),
    )
    review = validate_semantic_judgment(
        case,
        (),
        judgment,
        post._provenance(),
        expected_frontier=case.frontier,
        prior_finding_refs=frozenset({str(fnd(1))}),
        citable_refs=frozenset({str(fnd(1)), str(res(1)), str(res(2)), str(obl(2))}),
        provider_input_text_by_ref=index,
    )
    assert review.verified == ()  # A bad optional positive row never becomes evidence.
    assert review.snippets_rejected == int(bad_quote) + int(ruling == "reraised")
    gaps = tuple(sorted(_review_fence_gaps(review)))
    assert (_QUOTE in gaps) == (bad_quote or ruling == "reraised")
    check = replace(
        fr._check(
            tested=20,
            semantic=fr._SEMANTIC_OK,
            policies=((finding.policy_id, finding.policy_version),),
            coverage=fr._coverage(gaps=gaps, semantic=True),
        ),
        semantic_conclusion=judgment.conclusion,
        prior_finding_verdicts=review.verdicts,
    )
    blockers = resolution_blockers(
        finding, 5, check, frozenset(), proof_state=fr._changed_state(check, recorded_at=5)
    )
    if ruling == "fixed":
        assert [item.verdict for item in review.verdicts] == ["fixed"]
        assert review.verdicts[0].cited_refs == (res(2),)
        assert blockers == ()  # Paired production counterexample: identical qualification.
    elif ruling == "silence":
        assert review.verdicts == ()
        assert blockers == (("coverage:" + _QUOTE,) if bad_quote else ())
    else:
        assert [item.verdict for item in review.verdicts] == ["unassessable"]
        assert "reviewer_verdict_unassessable" in blockers
        if ruling == "reraised":
            assert len(review.candidates) == 1
            challenge = review.candidates[0].challenge
            assert challenge is not None and challenge.snippet is None
            assert review.candidates[0].related_finding_ids == (fnd(1),)


@pytest.mark.parametrize(
    ("guard", "expected"),
    [
        ("unchanged", "no_material_change_since_finding"),
        ("reraised", "issue_returned_again"),
        ("stale", "coverage:planned_verification_stale"),
        ("unknown", "freshness_unproven"),
        ("unreadable", "freshness_unproven"),
        ("reduced", "finding_material_outside_reduced_review_scope"),
    ],
)
def test_quote_tolerance_does_not_relax_other_fixed_ruling_proof_guards(
    guard: str, expected: str
) -> None:
    finding = fr._finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    gaps = (_QUOTE,)
    if guard == "stale":
        gaps += ("planned_verification_stale",)
    if guard == "reduced":
        gaps += ("semantic_reference_scope_reduced",)
        finding = replace(finding, coverage=fr._coverage(gaps=gaps[1:], semantic=True))
    freshness = {
        "unknown": LedgerFreshness.UNKNOWN,
        "unreadable": LedgerFreshness.REDACTED_GAP,
    }.get(guard, LedgerFreshness.PARTIAL)
    check = fr._ruled(
        fr._check(
            semantic=fr._SEMANTIC_OK,
            coverage=fr._coverage(gaps=gaps, semantic=True, freshness=freshness),
        ),
        (1, "fixed"),
        conclusion="no_material_discrepancy",
    )
    blockers = resolution_blockers(
        finding,
        4,
        check,
        frozenset({issue_key(finding)}) if guard == "reraised" else frozenset(),
        proof_state=None if guard == "unchanged" else fr._changed_state(check),
    )
    assert expected in blockers
    assert "coverage:" + _QUOTE not in blockers
    assert _QUOTE in check.coverage.known_gaps


def test_stale_verification_still_blocks_capture_baseline_reuse_until_cleared() -> None:
    finding = fr._semantic_finding("unpaired_event", "planned_verification_stale")
    for stale in (True, False):
        gaps = ("unpaired_event", _QUOTE) + (("planned_verification_stale",) if stale else ())
        check = fr._ruled(
            fr._review_check(*gaps), (1, "fixed"), conclusion="no_material_discrepancy"
        )
        blockers = resolution_blockers(
            finding, 4, check, frozenset(), proof_state=fr._changed_state(check)
        )
        assert blockers == (
            ("coverage:planned_verification_stale", "coverage:unpaired_event") if stale else ()
        )


def test_semantic_guidance_and_respond_replay_the_same_prefix_and_refresh_work_facts(
    command_key: None,
) -> None:
    ledger = ObservedLedger()
    obligation = ledger.plan("python3 verify.py")
    run = ledger.run("python3 verify.py", ResultOutcome.SUCCESS, exit_status=0)
    freshness.manifest(ledger, run, inputs=("src/fix.py",))
    finding = replace(
        fr._finding(
            origin=FindingOrigin.SEMANTIC_MODEL_DERIVED,
            subject_refs=(obligation,),
        ),
        subject_frontier=ledger.frontier,
    )
    ledger.append(EventSchema("finding_recorded", "1.3.0"), finding, observed=False)
    freshness.changed(ledger, "src/fix.py")
    review = replace(
        fr._review_check("planned_verification_stale", "semantic_reference_scope_reduced"),
        subject_frontier=ledger.frontier,
        semantic_conclusion="insufficient_packet",
    )
    ledger.append(EventSchema("check_recorded", "1.3.0"), review, observed=False)
    prefix = ledger.prefix
    state = replay(prefix)
    snapshot = projection_snapshot(state)
    before = finding_resolution_explanation(state, fnd(1), prefix)
    assert "Self-verification is unavailable now: finding_not_proof_limited" in before
    assert "coverage:planned_verification_stale" in before
    assert SELF_VERIFIED_GUIDANCE not in before
    ledger.run(
        "python3 verify.py", ResultOutcome.SUCCESS, exit_status=0, workspace_effect="unchanged"
    )
    local = replace(fr._check(), subject_frontier=ledger.frontier)
    ledger.append(EventSchema("check_recorded", "1.2.0"), local, observed=False)
    current = replay(ledger.prefix)
    attempt = finding_resolution_attempt(current, fnd(1), ledger.prefix)
    assert self_verification_evaluation(current, fnd(1), ledger.prefix, attempt=attempt) == (
        None,
        (),
    )
    assert self_verification_refusal(current, fnd(1), ledger.prefix) is None
    after = finding_resolution_explanation(current, fnd(1), ledger.prefix)
    assert "Self-verification is available now" in after
    assert "cannot read clean" in after
    assert not finding_is_resolved(current, fnd(1))
    # A later local check refreshes work facts only in its prefix; historical reads stay refused.
    assert finding_resolution_explanation(replay(prefix), fnd(1), prefix) == before
    assert (
        finding_resolution_explanation(projection_from_snapshot(snapshot), fnd(1), prefix) == before
    )
    assert projection_snapshot(state) == snapshot
