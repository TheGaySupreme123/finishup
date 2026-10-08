"""Readable completion claims compared with the sole plan scope authority."""

from __future__ import annotations

from dataclasses import dataclass, replace

from yoetz.domain.events import ClaimKind, ObligationStatus
from yoetz.domain.receipts import (
    COMPLETION_CLAIM_OUTSIDE_PLAN_GAP,
    COMPLETION_PLAN_NOT_CLAIMED_GAP,
)
from yoetz.domain.values import ClaimId, ObligationId
from yoetz.kernel.claims import effective_claim_items
from yoetz.kernel.plan_scope import current_plan_scope
from yoetz.kernel.projections import ProjectionState
from yoetz.protocol.coverage import Coverage, LedgerFreshness

# Keep the short names local to this comparison module while the canonical gap constants live with
# the other receipt gap vocabulary. Receipt/check consumers import the canonical names directly.
CLAIM_OUTSIDE_PLAN = COMPLETION_CLAIM_OUTSIDE_PLAN_GAP
PLAN_NOT_CLAIMED = COMPLETION_PLAN_NOT_CLAIMED_GAP
SCOPE_REPAIR = (
    "Add intended work with plan_revised obligation_changes change=carried, or publish a full "
    "plan_published restatement at exactly the next plan version. Alternatively replace the "
    "completion claim using claim_recorded/1.1.0 supersedes_claim_refs. A partial claim leaves "
    "the omitted plan scope outside its completion coverage; it does not reopen resolved work."
)


@dataclass(frozen=True, slots=True)
class CompletionScopeDifference:
    claim_id: ClaimId
    outside_plan: tuple[ObligationId, ...]
    not_claimed: tuple[ObligationId, ...]


def completion_scope_differences(state: ProjectionState) -> tuple[CompletionScopeDifference, ...]:
    """Compare each effective claim independently; never infer scope or merge claims.

    A prior claim remains effective until explicitly superseded. A later plan change, including an
    explicit waiver, therefore requires reviewing that assertion against the current scope too.
    Missing/unreadable inputs are left to the existing unknown-input coverage, never interpreted as
    an empty declaration.

    An obligation whose current status is ``acknowledged_not_done`` is outside completion coverage
    (tb4n2 R2, issue #1022): a completion claim that omits it is the honest claim, so it is never
    "plan not claimed". The acknowledgement stays disclosed by readiness and the receipt, which
    never reads clean while it stands; a claim that *names* it still raises the open-obligation
    finding. The status is read from the current projection on every call, so republishing the
    obligation open brings it back into coverage.
    """

    scope = current_plan_scope(state.plans, state.coverage_gaps)
    if not scope.has_plan or scope.effective_obligation_refs is None:
        return ()
    plan = frozenset(scope.effective_obligation_refs)
    differences: list[CompletionScopeDifference] = []
    for key, record in effective_claim_items(state):
        claim = record.payload
        if claim is None or claim.claim_kind is not ClaimKind.COMPLETION:
            continue
        refs = frozenset(claim.obligation_refs)
        if any(
            (row := state.obligations.get(ref)) is None or row.payload is None
            for ref in plan | refs
        ):
            continue
        acknowledged = frozenset(
            ref
            for ref in plan
            if (payload := state.obligations[ref].payload) is not None
            and payload.status is ObligationStatus.ACKNOWLEDGED_NOT_DONE
        )
        outside = tuple(sorted(refs - plan))
        missing = tuple(sorted(plan - refs - acknowledged))
        if outside or missing:
            differences.append(CompletionScopeDifference(key, outside, missing))
    return tuple(differences)


def completion_scope_codes(state: ProjectionState) -> tuple[str, ...]:
    differences = completion_scope_differences(state)
    return tuple(
        code
        for code, present in (
            (CLAIM_OUTSIDE_PLAN, any(row.outside_plan for row in differences)),
            (PLAN_NOT_CLAIMED, any(row.not_claimed for row in differences)),
        )
        if present
    )


def with_completion_scope_coverage(coverage: Coverage, state: ProjectionState) -> Coverage:
    codes = completion_scope_codes(state)
    if not codes:
        return coverage
    return replace(
        coverage,
        known_gaps=tuple(sorted(set(coverage.known_gaps) | set(codes))),
        ledger_freshness=min(coverage.ledger_freshness, LedgerFreshness.PARTIAL),
    )
