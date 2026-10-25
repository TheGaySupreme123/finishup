"""The draft receipt's criterion rows (#975): records, not correctness.

Each quoted task criterion is classified from records only: a current hook-observed passing run
linked to it, only the agent's own word, or neither. The rows list gaps first and the counts cover
every criterion.
"""

from __future__ import annotations

from builders.observed_runs import ObservedLedger
from finishup.domain.events import (
    ClaimKind,
    ClaimRecordedPayloadV1_1,
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
    ResultOutcome,
)
from finishup.domain.values import claim_id, obligation_id
from finishup.kernel.draft_receipt import MAX_DRAFT_CRITERIA, draft_criteria
from finishup.kernel.evidence_basis import build_evidence_view
from finishup.kernel.reducers import replay
from finishup.kernel.verification_coverage import (
    build_verification_coverage,
    criterion_obligations,
)

_TASK = (
    "The tool must write out.txt. Every row must be sorted by id. The report must list each "
    "failure."
)
_WRITE = "The tool must write out.txt."
_SORTED = "Every row must be sorted by id."
_OBLIGATION = EventSchema("obligation_published", "1.1.0")
_CLAIM = EventSchema("claim_recorded", "1.1.0")


def _obligation(
    ledger: ObservedLedger, number: int, criteria: str, *, resolved_by: object = None
) -> object:
    identifier = obligation_id(f"obl_00000000-0000-4000-8000-{number:012d}")
    ledger.append(
        _OBLIGATION,
        ObligationPublishedPayload(
            obligation_id=identifier,
            description=f"Requirement {number}",
            evidence_expectation="A recorded passing run.",
            status=ObligationStatus.OPEN if resolved_by is None else ObligationStatus.RESOLVED,
            acceptance_criteria=criteria,
            resolution_evidence_refs=() if resolved_by is None else (resolved_by,),  # type: ignore[arg-type]
            requested_items=(RequestedItem(RequestedItemKind.COMMAND, "pytest -q"),),
        ),
        observed=False,
    )
    return identifier


def _claim(
    ledger: ObservedLedger,
    number: int,
    obligation: object,
    *refs: object,
    limitations: tuple[object, ...] = (),
) -> object:
    identifier = claim_id(f"clm_00000000-0000-4000-8000-{number:012d}")
    ledger.append(
        _CLAIM,
        ClaimRecordedPayloadV1_1(
            claim_id=identifier,
            claim_kind=ClaimKind.COMPLETION,
            statement="Done.",
            supporting_refs=tuple(refs),  # type: ignore[arg-type]
            obligation_refs=(obligation,),  # type: ignore[arg-type]
            limitation_refs=limitations,  # type: ignore[arg-type]
        ),
        observed=False,
    )
    return identifier


def _draft(ledger: ObservedLedger):  # noqa: ANN202
    records = tuple(ledger.records)
    projection = replay(records)
    coverage = build_verification_coverage(projection, records, task_statement=_TASK)
    evidence = build_evidence_view(projection, records)
    return projection, draft_criteria(projection, records, coverage, evidence)


def _plan(ledger: ObservedLedger, *obligations: object) -> None:
    ledger.append(
        EventSchema("plan_published", "1.1.0"),
        PlanPublishedPayload(1, "Plan", obligations, task_statement=_TASK),  # type: ignore[arg-type]
        observed=False,
    )


def test_criteria_split_into_linked_pass_claim_only_and_none_with_gaps_first() -> None:
    ledger = ObservedLedger()
    passed = _obligation(ledger, 1, _SORTED)
    claimed = _obligation(ledger, 2, _WRITE)
    _plan(ledger, passed, claimed)
    run = ledger.passes("pytest -q")
    agent_run = ledger.run("make out", ResultOutcome.SUCCESS, exit_status=0, observed=False)
    _obligation(ledger, 1, _SORTED, resolved_by=run)
    _obligation(ledger, 2, _WRITE, resolved_by=agent_run)
    _claim(ledger, 1, passed, run)
    claim = _claim(ledger, 2, claimed)
    projection, draft = _draft(ledger)

    # The obligation that restates a task sentence is that criterion (the index's own rule).
    assert criterion_obligations(projection, _SORTED) == (passed,)
    by_quote = {row.excerpt: row for row in draft.rows}
    assert by_quote[_SORTED].standing == "linked_pass_current"
    assert by_quote[_SORTED].refs == (str(run),)
    assert by_quote[_WRITE].standing == "agent_claim_only"
    # Its claim, its own reported result and its marking the obligation resolved: only the
    # agent's word.
    assert set(by_quote[_WRITE].refs) <= {str(claim), str(claimed), str(agent_run)}
    assert str(claim) in by_quote[_WRITE].refs
    failure = "The report must list each failure."
    assert by_quote[failure].standing == "none" and by_quote[failure].refs == ()
    assert (draft.linked_pass_current, draft.agent_claim_only, draft.none) == (1, 1, 1)
    assert draft.total == 3
    # Gaps lead, so the display bound never hides one behind a linked pass.
    assert [row.standing for row in draft.rows] == [
        "none",
        "agent_claim_only",
        "linked_pass_current",
    ]
    assert len(draft.rows) <= MAX_DRAFT_CRITERIA


def test_an_agent_reported_success_is_a_claim_and_an_observed_failure_is_no_pass() -> None:
    ledger = ObservedLedger()
    reported = _obligation(ledger, 1, _SORTED)
    failed = _obligation(ledger, 2, _WRITE)
    _plan(ledger, reported, failed)
    agent_run = ledger.run("pytest -q", ResultOutcome.SUCCESS, exit_status=0, observed=False)
    _claim(ledger, 1, reported, agent_run)
    observed_failure = ledger.fail("pytest -q")
    _claim(ledger, 2, failed, limitations=(observed_failure,))
    _projection, draft = _draft(ledger)
    by_quote = {row.excerpt: row for row in draft.rows}
    # A result the agent reported, not one the hook observed, is only the agent's word.
    assert by_quote[_SORTED].standing == "agent_claim_only"
    assert str(agent_run) in by_quote[_SORTED].refs
    # An observed failure never reads as a linked pass; the claim beside it is still a claim.
    assert by_quote[_WRITE].standing == "agent_claim_only"
    assert str(observed_failure) not in by_quote[_WRITE].refs


def test_a_long_criterion_is_clipped_for_display_only() -> None:
    long = "The output must " + "keep every field " * 12 + "intact."
    ledger = ObservedLedger()
    identifier = _obligation(ledger, 1, long)
    _plan(ledger, identifier)
    _projection, draft = _draft(ledger)
    (row,) = [row for row in draft.rows if row.source == "obligation"]
    assert len(row.excerpt) <= 160 and row.excerpt.endswith("[cut]")
    assert row.refs == (str(identifier),)
