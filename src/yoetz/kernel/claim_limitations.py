"""Which results a v1.1 completion claim must name in ``limitation_refs``.

The replay reducer rejects a completion claim with ``limitation_refs_complete`` when it omits a
required result. This module is that rule, pure and shared, so a surface can name the required
result ids before the agent authors the claim and the claim succeeds the first time.

A result is required when its typed outcome is ``failure`` or ``partial``, a later observed run of
the same command has not superseded it (#909), it is not a hook-observed safe exploration, and it
is relevant to the claim's scope. A whole-task claim (no ``obligation_refs``) treats every result
as relevant; a scoped claim treats only results whose action names a claimed obligation, or names
no obligation, as relevant.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from yoetz.domain.events import ActionRecordedPayload, ResultOutcome, ResultRecordedPayload
from yoetz.domain.values import ActionId, EventId, ObligationId, ResultId
from yoetz.kernel.observed_failures import (
    ObservedFailureState,
    observed_action_is_exploratory,
    observed_failure_states_from_records,
)
from yoetz.kernel.projections import ProjectionRecord, ProjectionState

__all__ = [
    "DISCLOSABLE_LIMITING_OUTCOMES",
    "MAX_LISTED_REQUIRED_LIMITATION_IDS",
    "TYPED_LIMITING_OUTCOMES",
    "required_limitation_ids_for_projection",
    "required_limitation_result_ids",
    "result_is_relevant_to_claim_scope",
]

# A v1.1 completion claim must disclose every relevant typed non-success result. An `unknown`
# outcome is not upgraded into a typed partial or failure (ADR-025 decision 3), so it is never
# required -- but it is limiting to the local limitation policy, so `limitation_refs` also
# accepts it as the disclosure channel a v1.1 claim would otherwise have none of.
TYPED_LIMITING_OUTCOMES: Final = frozenset({ResultOutcome.FAILURE, ResultOutcome.PARTIAL})
DISCLOSABLE_LIMITING_OUTCOMES: Final = TYPED_LIMITING_OUTCOMES | {ResultOutcome.UNKNOWN}
# Surfaces list at most this many ids, then the count of the rest.
MAX_LISTED_REQUIRED_LIMITATION_IDS: Final = 64


def result_is_relevant_to_claim_scope(
    claim_scope: frozenset[ObligationId],
    result_record: ProjectionRecord[ResultRecordedPayload],
    actions: Mapping[ActionId, ProjectionRecord[ActionRecordedPayload]],
    *,
    claim_frontier: int,
) -> bool:
    """Whether a recorded result is in the scope of a claim over ``claim_scope``."""

    if result_record.payload is None or result_record.source_frontier > claim_frontier:
        return False
    action = actions.get(result_record.payload.action_id)
    if action is None or action.payload is None:
        return True
    action_scope = frozenset(action.payload.obligation_refs)
    return not claim_scope or not action_scope or not claim_scope.isdisjoint(action_scope)


def required_limitation_result_ids(
    results: Mapping[ResultId, ProjectionRecord[ResultRecordedPayload]],
    actions: Mapping[ActionId, ProjectionRecord[ActionRecordedPayload]],
    observed_event_ids: frozenset[EventId],
    *,
    claim_scope: frozenset[ObligationId],
    claim_frontier: int,
) -> frozenset[ResultId]:
    """The result ids a completion claim at ``claim_frontier`` must name in ``limitation_refs``."""

    # A hook-observed failure that a later run of the same command superseded is no longer
    # required (#909). An edit alone changes the state under test without proving a covering
    # rerun, so it remains live and nameable.
    observed_states = observed_failure_states_from_records(
        results,
        actions,
        observed_event_ids,
        through=claim_frontier,
    )
    return frozenset(
        result_id_value
        for result_id_value, record in results.items()
        if record.payload is not None
        and record.payload.outcome in TYPED_LIMITING_OUTCOMES
        and observed_states.get(result_id_value, ObservedFailureState.LIVE)
        is ObservedFailureState.LIVE
        and not (
            (action := actions.get(record.payload.action_id)) is not None
            and action.payload is not None
            and action.source_event_id in observed_event_ids
            and observed_action_is_exploratory(action.payload)
        )
        and result_is_relevant_to_claim_scope(
            claim_scope,
            record,
            actions,
            claim_frontier=claim_frontier,
        )
    )


def required_limitation_ids_for_projection(
    state: ProjectionState,
    observed_event_ids: frozenset[EventId],
    *,
    claim_scope: frozenset[ObligationId] = frozenset(),
) -> tuple[ResultId, ...]:
    """Sorted ids a completion claim recorded next on ``state`` must name in ``limitation_refs``.

    The next claim lands after the projection's frontier, so every recorded result is in its
    frontier. The default empty ``claim_scope`` is a whole-task claim.
    """

    if type(state) is not ProjectionState:
        raise ValueError("required_limitations_invalid")
    return tuple(
        sorted(
            required_limitation_result_ids(
                state.results,
                state.actions,
                observed_event_ids,
                claim_scope=claim_scope,
                claim_frontier=state.frontier,
            ),
            key=str.encode,
        )
    )
