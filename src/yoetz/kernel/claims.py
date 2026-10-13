"""Shared append-only claim revision and limitation-scope derivations."""

from __future__ import annotations

from yoetz.domain.events import (
    ClaimKind,
    ClaimRecordedPayload,
    ClaimRecordedPayloadV1_1,
)
from yoetz.domain.values import ClaimId, ObligationId, ResultId
from yoetz.kernel.claim_limitations import scope_with_supersession_ancestry
from yoetz.kernel.projections import ClaimProjectionRecord, ProjectionState

__all__ = [
    "claim_discloses_result",
    "completion_claim_present",
    "effective_claim_items",
    "effective_claim_ids",
    "result_is_relevant_to_claim",
]

type ClaimPayload = ClaimRecordedPayload | ClaimRecordedPayloadV1_1
type ClaimRecord = ClaimProjectionRecord


def effective_claim_ids(projection: ProjectionState) -> frozenset[ClaimId]:
    """Return claims not explicitly replaced by a v1.1 correction.

    The edge is read from the durable ``superseded_by_claim_id`` the projection records on the
    target, not from the replacement's live ``supersedes_claim_refs``: redacting the middle of a
    C0 <- C1 <- C2 chain tombstones C1's payload, and a payload-derived reading would resurrect C0
    as a second current claim beside C2.
    """

    return frozenset(
        claim
        for claim, record in projection.claims.items()
        if record.superseded_by_claim_id is None
    )


def effective_claim_items(
    projection: ProjectionState,
) -> tuple[tuple[ClaimId, ClaimRecord], ...]:
    """Return effective claims in stable claim-id order; history remains in the projection."""

    effective = effective_claim_ids(projection)
    return tuple((claim, projection.claims[claim]) for claim in sorted(effective, key=str.encode))


def completion_claim_present(projection: ProjectionState) -> bool:
    """Whether any effective, readable claim at this frontier is a completion claim."""

    return any(
        record.payload is not None and record.payload.claim_kind is ClaimKind.COMPLETION
        for _, record in effective_claim_items(projection)
    )


def _scope(payload: ClaimPayload) -> frozenset[ObligationId]:
    return frozenset(payload.obligation_refs)


def result_is_relevant_to_claim(
    projection: ProjectionState,
    claim_record: ClaimRecord,
    result_ref: ResultId,
) -> bool:
    """Whether a result existed by the claim and overlaps its declared obligation scope."""

    claim = claim_record.payload
    result = projection.results.get(result_ref)
    if (
        claim is None
        or result is None
        or result.payload is None
        or result.source_frontier > claim_record.source_frontier
    ):
        return False
    action = projection.actions.get(result.payload.action_id)
    if action is None or action.payload is None:
        return True
    # tb4n5: a plan correction carries the claim's scope to the superseded obligations.
    claim_scope = scope_with_supersession_ancestry(_scope(claim), projection.obligations)
    action_scope = frozenset(action.payload.obligation_refs)
    return not claim_scope or not action_scope or not claim_scope.isdisjoint(action_scope)


def claim_discloses_result(
    claim: ClaimPayload,
    result_ref: ResultId,
) -> bool:
    """Apply the versioned disclosure field without reinterpreting frozen v1 bytes."""

    if type(claim) is ClaimRecordedPayloadV1_1:
        return result_ref in claim.limitation_refs
    return result_ref in claim.supporting_refs
