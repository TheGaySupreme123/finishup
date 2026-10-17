"""Which recorded evidence and result ids are admissible for one obligation.

The Stop gate's flagged acceptance line cites an ``evd_`` or ``res_`` id. Shape is not enough:
the id has to be a ledger row linked to that obligation, to a target the obligation requested,
or to a claim that lists that obligation, at or before the closing frontier, and the row itself
has to be an observed verification or be linked to one. A claim that lists no obligation does
not lend its supporting ids. An id the agent only asserted is unattested. This module only
reads those links. It does not grade whether the evidence is true, and it does not reject a
claim.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from finishup.domain.events import (
    ActionRecordedPayload,
    LedgerRecord,
    ObligationPublishedPayload,
    ResultRecordedPayload,
    is_observation_authored,
)
from finishup.domain.values import ActionId, EventId, EvidenceId, ObligationId, ResultId
from finishup.kernel.claims import effective_claim_items
from finishup.kernel.command_attempts import value_in_attempted
from finishup.kernel.evidence_alignment import results_by_evidence, source_actions
from finishup.kernel.observed_failures import is_observed_run_record
from finishup.kernel.projections import ProjectionState

__all__ = ["MAX_ADMISSIBLE_OBLIGATIONS", "MAX_ADMISSIBLE_REFS", "admissible_verification_refs"]

MAX_ADMISSIBLE_OBLIGATIONS: int = 8
MAX_ADMISSIBLE_REFS: int = 8


def admissible_verification_refs(
    projection: ProjectionState,
    records: tuple[LedgerRecord, ...],
    obligations: Iterable[ObligationId],
    *,
    limit: int | None = MAX_ADMISSIBLE_OBLIGATIONS,
) -> tuple[tuple[ObligationId, tuple[str, ...]], ...]:
    """``(obligation, sorted evd_/res_ ids)`` for obligations that have an observed link.

    An id is admissible when its projection row is readable at or before ``projection.frontier``,
    its source event is in *records* at or before that frontier, one recorded link holds, and
    the id is an observed verification or is linked to one. A recorded link is: the obligation's
    ``resolution_evidence_refs`` cite it; ``source_actions`` names an action that lists the
    obligation, or lists no obligation and names one of its requested items; or an effective
    claim's ``supporting_refs`` contain it and the claim lists that obligation. A claim with
    empty ``obligation_refs`` lends nothing. Observed means hook-captured or observation-captured
    evidence (observation-authored ``evidence_recorded``) or a result of an observed command
    (``is_observed_run_record`` on the result or on its action), including an id whose
    ``source_actions`` reach such a row. An agent-asserted id with no such row is omitted.
    A global action with no attempted item is not a link. At most eight ids each, sorted. An
    obligation with no such id is omitted. *limit* bounds the obligations walked (the first
    eight in id order by default, for the bounded status field); ``None`` walks every one, as
    the coverage judgement and the receipt pairing must.
    """

    if type(projection) is not ProjectionState or type(records) is not tuple:
        return ()
    frontier = projection.frontier
    by_event = {row.event_id: row for row in records if row.ledger.ingestion_sequence <= frontier}
    evidence_actions = results_by_evidence(projection)
    source_cache: dict[str, tuple[tuple[ActionRecordedPayload, EventId], ...]] = {}
    claim_refs = _claim_refs(projection, frontier, by_event)
    rows: list[tuple[ObligationId, tuple[str, ...]]] = []
    for obligation in tuple(sorted(set(obligations), key=str.encode))[:limit]:
        refs = _refs_for(
            projection,
            frontier,
            by_event,
            evidence_actions,
            source_cache,
            obligation,
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
) -> dict[ObligationId, frozenset[str]]:
    """Supporting ``evd_``/``res_`` ids from claims that list each obligation.

    A claim with empty ``obligation_refs`` is a bounded assertion. It does not lend those ids
    to any obligation.
    """

    by_obligation: dict[ObligationId, set[str]] = {}
    for _claim_id, record in effective_claim_items(projection):
        if not _current(record, frontier, by_event):
            continue
        payload = record.payload
        if payload is None or not payload.obligation_refs:
            continue
        tokens = tuple(
            str(ref) for ref in payload.supporting_refs if str(ref).startswith(("evd_", "res_"))
        )
        for obligation in payload.obligation_refs:
            by_obligation.setdefault(obligation, set()).update(tokens)
    return {key: frozenset(value) for key, value in by_obligation.items()}


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
    claim_refs: frozenset[str],
) -> tuple[str, ...]:
    record = projection.obligations.get(obligation)
    raw_payload = (
        record.payload if record is not None and _current(record, frontier, by_event) else None
    )
    payload = raw_payload if type(raw_payload) is ObligationPublishedPayload else None
    found: set[str] = set(claim_refs)
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
        if _current(_row(projection, ref), frontier, by_event) and _observed_ref(
            projection, by_event, evidence_actions, source_cache, ref
        ):
            admissible.append(ref)
        if len(admissible) == MAX_ADMISSIBLE_REFS:
            break
    return tuple(admissible)


def _observed_verification_record(record: LedgerRecord) -> bool:
    """Hook-captured or observation-captured evidence, or an observed command or its result."""

    if is_observed_run_record(record):
        return True
    return record.schema.name == "evidence_recorded" and is_observation_authored(record)


def _observed_ref(
    projection: ProjectionState,
    by_event: Mapping[EventId, LedgerRecord],
    evidence_actions: Mapping[str, tuple[ActionId, ...]],
    source_cache: dict[str, tuple[tuple[ActionRecordedPayload, EventId], ...]],
    ref: str,
) -> bool:
    """Whether *ref* is an observed verification row or is linked to one.

    Digest provenance is not enough: an agent-asserted id stays unattested until FinishUP
    observed the evidence, the command, or a row this id's source actions reach.
    """

    row = _row(projection, ref)
    if row is None:
        return False
    source_event_id = getattr(row, "source_event_id", None)
    if type(source_event_id) is str:
        source = by_event.get(EventId(source_event_id))
        if source is not None and _observed_verification_record(source):
            return True
    payload = getattr(row, "payload", None)
    if type(payload) is ResultRecordedPayload:
        action = projection.actions.get(payload.action_id)
        action_event = None if action is None else action.source_event_id
        if type(action_event) is str:
            action_source = by_event.get(EventId(action_event))
            if action_source is not None and is_observed_run_record(action_source):
                return True
    for _action, event in source_actions(projection, by_event, ref, evidence_actions, source_cache):
        linked = by_event.get(event)
        if linked is not None and _observed_verification_record(linked):
            return True
    return False
