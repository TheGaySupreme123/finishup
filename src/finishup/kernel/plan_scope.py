"""Derived current-plan completion scope.

The plan chain is the only authority for completion scope.  This module deliberately accepts
only projected plan records and projection gap markers: prompts, workspace state, source code,
and free-form plan prose never contribute obligations.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from finishup.domain.events import (
    NoObligationsReason,
    ObligationChangeKind,
    PlanPublishedPayload,
    PlanRevisedPayload,
)
from finishup.domain.values import EventId, ObligationId, event_id
from finishup.kernel.projections import PlanProjectionRecord

__all__ = ["CurrentPlanScope", "current_plan_scope"]


def _ascii(value: str) -> bytes:
    return value.encode("ascii")


@dataclass(frozen=True, slots=True)
class CurrentPlanScope:
    """One conservative reading of the current plan chain.

    ``None`` references/count mean that a plan exists but its effective declaration cannot be
    read.  No plan is a distinct, readable state: ``has_plan`` is false and the references are an
    empty tuple, while the declared count remains absent because there was no declaration.
    """

    current_plan_event_id: EventId | None
    effective_obligation_refs: tuple[ObligationId, ...] | None
    declared_obligation_count: int | None
    no_obligations_reason: NoObligationsReason | None

    @property
    def has_plan(self) -> bool:
        return self.current_plan_event_id is not None

    @property
    def readable(self) -> bool:
        return not self.has_plan or self.effective_obligation_refs is not None


def _unknown_plan_event_ids(coverage_gaps: tuple[str, ...]) -> tuple[EventId, ...]:
    found: set[EventId] = set()
    for marker in coverage_gaps:
        if not marker.startswith("unknown_event:"):
            continue
        parts = marker.split(":", 2)
        if len(parts) != 3:
            continue
        schema_identity = parts[2]
        if not (
            schema_identity.startswith("plan_published@")
            or schema_identity.startswith("plan_revised@")
        ):
            continue
        try:
            found.add(event_id(parts[1]))
        except ValueError:
            # ProjectionState already validates registered gap shapes. Keep this helper total for
            # direct callers and let the ordinary projection-corruption boundary own bad markers.
            continue
    return tuple(sorted(found, key=lambda value: _ascii(str(value))))


def current_plan_scope(
    plans: Mapping[int, PlanProjectionRecord],
    coverage_gaps: tuple[str, ...] = (),
) -> CurrentPlanScope:
    """Return the effective scope declared by one readable, ordered plan chain.

    A second root, a disconnected revision, a redacted plan payload, or an unknown-version plan
    event makes the declaration unreadable.  That state is never collapsed to zero obligations.
    Revisions restate the optional empty-scope reason, so omission clears an earlier reason.
    """

    ordered = tuple(
        sorted(
            plans.values(),
            key=lambda record: (record.source_frontier, _ascii(str(record.source_event_id))),
        )
    )
    unknown_plan_events = _unknown_plan_event_ids(coverage_gaps)
    if not ordered and not unknown_plan_events:
        return CurrentPlanScope(None, (), None, None)

    current_event: EventId | None = None
    current_version: int | None = None
    obligations: set[ObligationId] = set()
    reason: NoObligationsReason | None = None
    readable = True

    for record in ordered:
        current_event = record.source_event_id
        payload = record.payload
        if payload is None:
            readable = False
            continue
        if type(payload) is PlanPublishedPayload:
            # A later plan_published is an append-only full-scope restatement. It is readable
            # only when it advances the current chain by exactly one version; a duplicate root
            # or version gap remains conservative unknown. This gives a task one admitted way to
            # declare a newly material obligation without pretending it superseded an older one.
            if current_version is not None and payload.plan_version != current_version + 1:
                readable = False
                continue
            current_version = payload.plan_version
            obligations = set(payload.obligation_refs)
            reason = payload.no_obligations_reason
            continue
        if type(payload) is not PlanRevisedPayload:
            readable = False
            continue
        if current_version is None or payload.supersedes_plan_version != current_version:
            readable = False
            continue
        current_version = payload.plan_version
        for change in payload.obligation_changes:
            if change.change is ObligationChangeKind.SUPERSEDED:
                obligations.discard(change.obligation_id)
                obligations.update(change.replacement_obligation_ids)
            elif change.change is ObligationChangeKind.WAIVED:
                obligations.discard(change.obligation_id)
            else:
                obligations.add(change.obligation_id)
        reason = payload.no_obligations_reason

    if unknown_plan_events:
        current_event = unknown_plan_events[-1]
        readable = False
    if current_event is None:
        # Only malformed/unknown plan markers can reach this branch; they still prove that a plan
        # family was present while leaving its declaration unreadable.
        current_event = unknown_plan_events[-1]
    if not readable or current_version is None:
        return CurrentPlanScope(current_event, None, None, None)
    ordered_obligations = tuple(sorted(obligations, key=lambda value: _ascii(str(value))))
    return CurrentPlanScope(
        current_event,
        ordered_obligations,
        len(ordered_obligations),
        reason,
    )
