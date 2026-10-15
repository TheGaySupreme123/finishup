"""Which recorded evidence and result ids are admissible for one obligation.

The Stop gate's flagged acceptance line cites an ``evd_`` or ``res_`` id. Shape is not enough:
the id has to be a ledger row linked to that obligation, to a target the obligation requested,
or to a task-scoped claim, at or before the closing frontier. This module only reads those
links. It does not grade whether the evidence is true, and it does not reject a claim.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from finishup.domain.events import (
    ActionRecordedPayload,
    LedgerRecord,
    ObligationPublishedPayload,
)
from finishup.domain.values import ActionId, EventId, EvidenceId, ObligationId, ResultId
from finishup.kernel.claims import effective_claim_items
from finishup.kernel.command_attempts import value_in_attempted
from finishup.kernel.evidence_alignment import results_by_evidence, source_actions
from finishup.kernel.projections import ProjectionState

__all__ = ["MAX_ADMISSIBLE_OBLIGATIONS", "MAX_ADMISSIBLE_REFS", "admissible_verification_refs"]

MAX_ADMISSIBLE_OBLIGATIONS: int = 8
MAX_ADMISSIBLE_REFS: int = 8


def admissible_verification_refs(
    projection: ProjectionState,
    records: tuple[LedgerRecord, ...],
    obligations: Iterable[ObligationId],
) -> tuple[tuple[ObligationId, tuple[str, ...]], ...]:
    """``(obligation, sorted evd_/res_ ids)`` for obligations that have a recorded link.

    An id is admissible when its projection row is readable at or before ``projection.frontier``,
    its source event is in *records* at or before that frontier, and one recorded link holds:
    the obligation's ``resolution_evidence_refs`` cite it; ``source_actions`` names an action
    that lists the obligation, or lists no obligation and names one of its requested items; or
    an effective claim's ``supporting_refs`` contain it and the claim lists the obligation or
    lists none (the whole task). A global action with no attempted item is not a link. At most
    eight obligations and eight ids each, sorted. An obligation with no such id is omitted.
    """

    if type(projection) is not ProjectionState or type(records) is not tuple:
        return ()
    frontier = projection.frontier
    by_event = {row.event_id: row for row in records if row.ledger.ingestion_sequence <= frontier}
    evidence_actions = results_by_evidence(projection)
    source_cache: dict[str, tuple[tuple[ActionRecordedPayload, EventId], ...]] = {}
    task_refs, claim_refs = _claim_refs(projection, frontier, by_event)
    rows: list[tuple[ObligationId, tuple[str, ...]]] = []
    for obligation in tuple(sorted(set(obligations), key=str.encode))[:MAX_ADMISSIBLE_OBLIGATIONS]:
        refs = _refs_for(
            projection,
            frontier,
            by_event,
            evidence_actions,
            source_cache,
            obligation,
            task_refs,
            claim_refs.get(obligation, frozenset()),
        )
        if refs:
            rows.append((obligation, refs))
    return tuple(rows)


def _current(
    record: object,
    frontier: int,
    by_event: Mapping[EventId, LedgerRecord],
) -> bool:
    """Whether *record* is a readable projection row at or before *frontier*.

    *record* is one projection row. The generic row type is invariant, so this reads the
    shared fields without naming that type.
    """

    payload = getattr(record, "payload", None)
    redacted = getattr(record, "redacted", None)
    source_frontier = getattr(record, "source_frontier", None)
    source_event_id = getattr(record, "source_event_id", None)
    if payload is None or redacted is not False:
        return False
    if type(source_frontier) is not int or source_frontier > frontier:
        return False
    if type(source_event_id) is not str:
        return False
    source = by_event.get(EventId(source_event_id))
    return source is not None and source.ledger.ingestion_sequence <= frontier


def _claim_refs(
    projection: ProjectionState,
    frontier: int,
    by_event: Mapping[EventId, LedgerRecord],
) -> tuple[frozenset[str], dict[ObligationId, frozenset[str]]]:
    task: set[str] = set()
    by_obligation: dict[ObligationId, set[str]] = {}
    for _claim_id, record in effective_claim_items(projection):
        if not _current(record, frontier, by_event):
            continue
        payload = record.payload
        if payload is None:
            continue
        tokens = tuple(
            str(ref) for ref in payload.supporting_refs if str(ref).startswith(("evd_", "res_"))
        )
        if not payload.obligation_refs:
            task.update(tokens)
            continue
        for obligation in payload.obligation_refs:
            by_obligation.setdefault(obligation, set()).update(tokens)
    return frozenset(task), {key: frozenset(value) for key, value in by_obligation.items()}


def _row(projection: ProjectionState, ref: str) -> object:
    if ref.startswith("res_"):
        return projection.results.get(ResultId(ref))
    if ref.startswith("evd_"):
        return projection.evidence.get(EvidenceId(ref))
    return None


def _action_covers(
    action: ActionRecordedPayload,
    obligation: ObligationId,
    payload: ObligationPublishedPayload | None,
) -> bool:
    if obligation in action.obligation_refs:
        return True
    # An action that names other obligations covers only those. One that names none is not
    # global: it covers an obligation only when it names one of that obligation's requested items.
    if action.obligation_refs or payload is None or not action.attempted_items:
        return False
    return any(
        value_in_attempted(item.value, action.attempted_items) for item in payload.requested_items
    )


def _refs_for(
    projection: ProjectionState,
    frontier: int,
    by_event: Mapping[EventId, LedgerRecord],
    evidence_actions: Mapping[str, tuple[ActionId, ...]],
    source_cache: dict[str, tuple[tuple[ActionRecordedPayload, EventId], ...]],
    obligation: ObligationId,
    task_refs: frozenset[str],
    claim_refs: frozenset[str],
) -> tuple[str, ...]:
    record = projection.obligations.get(obligation)
    raw_payload = (
        record.payload if record is not None and _current(record, frontier, by_event) else None
    )
    payload = raw_payload if type(raw_payload) is ObligationPublishedPayload else None
    found: set[str] = set(task_refs)
    found.update(claim_refs)
    if payload is not None:
        found.update(
            str(ref)
            for ref in payload.resolution_evidence_refs
            if str(ref).startswith(("evd_", "res_"))
        )
    for ref, row in (
        *((str(key), value) for key, value in projection.results.items()),
        *((str(key), value) for key, value in projection.evidence.items()),
    ):
        if not _current(row, frontier, by_event):
            continue
        for action, event in source_actions(
            projection, by_event, ref, evidence_actions, source_cache
        ):
            if event in by_event and _action_covers(action, obligation, payload):
                found.add(ref)
                break
    admissible: list[str] = []
    for ref in sorted(found, key=str.encode):
        if _current(_row(projection, ref), frontier, by_event):
            admissible.append(ref)
        if len(admissible) == MAX_ADMISSIBLE_REFS:
            break
    return tuple(admissible)
