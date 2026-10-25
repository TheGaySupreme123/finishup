"""The draft receipt's criterion rows: records, not correctness (#975, ADR-046 amendment).

Before the final receipt the agent sees a draft of what the receipt will say, so it can keep
working when it sees a problem. The draft's conclusion and reasons are the receipt prediction
itself (``kernel.receipt_prediction``); this module adds the one thing the prediction does not
say: for each quoted task criterion, what the record links to it.

* ``linked_pass_current``: a hook-observed run that succeeded, is current (no later material
  change), and links to the criterion: through a verification manifest that quotes it (with no
  failing case), or through an obligation whose acceptance criteria state it.
* ``agent_claim_only``: no such run, but the agent's own word stands behind it: a claim on such
  an obligation, a result the agent reported rather than one the hook observed, a manifest whose
  run is not a current observed pass, or the agent marking the obligation resolved.
* ``none``: neither.

The criteria are the declared-coverage index's own (``build_verification_coverage``: the task
statement's sentences and the obligations' acceptance criteria). Links are the whole explicit
relation index the evidence view is built from (``evidence_scopes``, read before any display
bound) and the manifests that quote the criterion; no text similarity links anything. A linked passing run says nothing about whether the run
measures the criterion, so no surface calls a row verified.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final, Literal

from finishup.domain.bounded_text import clip_to_limit
from finishup.domain.events import LedgerRecord, ObligationStatus, ResultOutcome
from finishup.domain.values import ResultId
from finishup.domain.verification_coverage import CriterionSource, VerificationCoverage
from finishup.kernel.evidence_basis import evidence_scopes
from finishup.kernel.observed_failures import is_observed_run_record
from finishup.kernel.projections import ProjectionState
from finishup.kernel.verification_coverage import criterion_obligations
from finishup.kernel.verification_freshness import (
    VerificationFreshness,
    verification_freshness,
    verification_tracked_runs,
)

__all__ = [
    "DRAFT_STANDINGS",
    "MAX_DRAFT_CRITERIA",
    "MAX_DRAFT_EXCERPT_CHARS",
    "DraftCriteria",
    "DraftCriterion",
    "DraftStanding",
    "draft_criteria",
]

DraftStanding = Literal["linked_pass_current", "agent_claim_only", "none"]
# Display order: a criterion with nothing behind it first, then one only the agent vouches for,
# so the bound never hides a gap behind a linked pass.
DRAFT_STANDINGS: Final[tuple[DraftStanding, ...]] = (
    "none",
    "agent_claim_only",
    "linked_pass_current",
)
MAX_DRAFT_CRITERIA: Final = 6
# A display excerpt of the quoted sentence (the full quote is status view=coverage).
MAX_DRAFT_EXCERPT_CHARS: Final = 160
_MAX_REFS: Final = 3
_CUT: Final = " [cut]"


@dataclass(frozen=True, slots=True)
class DraftCriterion:
    excerpt: str
    source: CriterionSource
    standing: DraftStanding
    refs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DraftCriteria:
    # At most ``MAX_DRAFT_CRITERIA`` rows, gaps first; the counts cover every assessed criterion.
    rows: tuple[DraftCriterion, ...]
    # Every candidate criterion, including those the coverage index's own bound omitted.
    total: int
    linked_pass_current: int
    agent_claim_only: int
    none: int


def _refs(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))[:_MAX_REFS]


def draft_criteria(
    projection: ProjectionState,
    records: tuple[LedgerRecord, ...],
    coverage: VerificationCoverage,
    *,
    freshness: tuple[VerificationFreshness, ...] | None = None,
    tracked_runs: tuple[ResultId, ...] | None = None,
) -> DraftCriteria:
    """Classify each criterion of *coverage* by what the record links to it (pure).

    Links are read from the whole explicit relation index (``evidence_scopes``), never from a
    display-bounded view: a claim or a passing run past any listing bound still counts, so a
    criterion never reads ``none`` (or a pass ``agent_claim_only``) because a list was capped.
    Only the output rows and refs are bounded. Freshness is the evidence view's own rule: a
    tracked run without a stale row is current; an untracked run is never current.
    """

    index = evidence_scopes(projection, records)
    prefix = index.prefix
    rows_by_run = verification_freshness(projection, prefix) if freshness is None else freshness
    tracked = frozenset(
        verification_tracked_runs(projection, prefix) if tracked_runs is None else tracked_runs
    )
    fresh_by_run = {row.run_ref: row.state for row in rows_by_run}

    def observed(result: ResultId) -> bool:
        row = projection.results.get(result)
        if row is None or row.payload is None:
            return False
        action = projection.actions.get(row.payload.action_id)
        sources = (
            index.by_event.get(str(row.source_event_id)),
            None if action is None else index.by_event.get(str(action.source_event_id)),
        )
        return any(record is not None and is_observed_run_record(record) for record in sources)

    def current(result: ResultId) -> bool:
        return result in tracked and fresh_by_run.get(result, "current") == "current"

    def succeeded(result: ResultId) -> bool:
        row = projection.results.get(result)
        return (
            row is not None
            and row.payload is not None
            and row.payload.outcome is ResultOutcome.SUCCESS
        )

    def no_failing_case(result: ResultId) -> bool:
        row = projection.results.get(result)
        manifest = None if row is None or row.payload is None else row.payload.verification
        return manifest is None or not manifest.failing

    # Every readable claim and result, by the obligations it explicitly concerns (uncapped).
    claims_by: dict[str, list[str]] = {}
    for key, row in index.claims:
        if row.payload is not None and str(key) in index.readable:
            for obligation in index.scopes.get(str(key), ()):
                claims_by.setdefault(str(obligation), []).append(str(key))
    results_by: dict[str, list[ResultId]] = {}
    for key, row in sorted(
        projection.results.items(), key=lambda item: (-item[1].source_frontier, str(item[0]))
    ):
        if row.payload is not None and str(key) in index.readable:
            for obligation in index.scopes.get(str(key), ()):
                results_by.setdefault(str(obligation), []).append(key)

    rows: list[DraftCriterion] = []
    for criterion in coverage.criteria:
        passing: list[str] = []
        vouched: list[str] = []
        for witness in criterion.witnesses:
            if (
                witness.freshness == "current"
                and witness.cases > 0
                and witness.failing == 0
                and succeeded(witness.result_id)
                and observed(witness.result_id)
            ):
                passing.append(str(witness.result_id))
            else:
                vouched.append(str(witness.result_id))
        obligations = criterion_obligations(projection, criterion.criterion_quote)
        for obligation in obligations:
            for result in results_by.get(str(obligation), ()):
                if not succeeded(result):
                    continue
                if observed(result):
                    if current(result) and no_failing_case(result):
                        passing.append(str(result))
                else:
                    vouched.append(str(result))
            vouched.extend(claims_by.get(str(obligation), ()))
            payload = projection.obligations[obligation].payload
            if payload is not None and payload.status is ObligationStatus.RESOLVED:
                vouched.append(str(obligation))
        standing: DraftStanding
        if passing:
            standing, refs = "linked_pass_current", _refs(passing)
        elif vouched:
            standing, refs = "agent_claim_only", _refs(vouched)
        else:
            standing, refs = "none", _refs(str(item) for item in obligations)
        excerpt = clip_to_limit(
            " ".join(criterion.criterion_quote.split()),
            MAX_DRAFT_EXCERPT_CHARS,
            marker=_CUT,
            ascii_only=False,
        )
        rows.append(DraftCriterion(excerpt, criterion.source, standing, refs))
    counts = {
        standing: sum(row.standing == standing for row in rows) for standing in DRAFT_STANDINGS
    }
    # A stable sort: gaps first, the index's own order (task criteria first) within a standing.
    listed = sorted(rows, key=lambda row: DRAFT_STANDINGS.index(row.standing))
    return DraftCriteria(
        tuple(listed[:MAX_DRAFT_CRITERIA]),
        len(coverage.criteria) + coverage.omitted_criteria,
        counts["linked_pass_current"],
        counts["agent_claim_only"],
        counts["none"],
    )
