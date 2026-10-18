"""Which resolved obligations the ledger flags as risky to call met (tb4n5, issue #1050, ADR-033).

The flags read provenance (attempts and evidence lineage), never outputs or test results. Until
owner decision D1 (2026-10-18) they drove a Stop-time acceptance re-read; in n7 agents answered it
by re-attesting "met" in 43 of 49 Stops and it never caught a failed obligation. Since D1 a flagged
obligation with no admissible observed link and no recorded verification limit is a receipt
coverage limit (``claim_verification.unresolved_acceptance_risk``), named once in status, and is
never a Stop item. The owner's rule (2026-10-13) for which resolutions are flagged, from facts the
record already holds:

* ``requested_item_never_attempted``: an output, command or other non-input item the obligation
  requested has no attempt (no ``attempted_items`` entry in any spelling, and, for a command, no
  hook-observed run matching it, ADR-045);
* ``evidence_not_linked_to_declared_items``: the obligation declares deliverables or commands, and
  no cited resolution evidence traces through a recorded link to an action that names one
  (``kernel.evidence_alignment``: the inspection's ``evidence_off_declared_items`` or
  ``evidence_unattributed``);
* ``evidence_self_asserted_only``: no cited resolution reference is corroborated by FinishUP (a
  hook-observed run or its result, observation-captured evidence, an approved check or an import
  report), and no requested command item has a matching observed run linked to it.

Pure and replay-derived over one projection and its record prefix; nothing is stored, and a ledger
replays to the same set after a restart, a reattach or an upgrade. Every value is an id or a closed
reason token.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Final

from finishup.domain.events import (
    ActionRecordedPayload,
    EvidenceDigestProvenance,
    EvidenceRecordedPayload,
    LedgerRecord,
    ObligationPublishedPayload,
    RequestedItem,
    RequestedItemKind,
    RequestedItemRole,
    is_observation_authored,
)
from finishup.domain.values import ActionId, EventId, EvidenceId, ObligationId, ResultId
from finishup.kernel.command_attempts import command_attempts, value_in_attempted
from finishup.kernel.evidence_alignment import (
    alignment_of,
    declared_items,
    evidence_sources,
    results_by_evidence,
)
from finishup.kernel.observed_failures import observed_event_ids_from_records
from finishup.kernel.projections import ProjectionState
from finishup.kernel.task_facts import (
    command_identity_key_generation,
    cooperative_event_ids_from_records,
    observed_planned_commands,
)

__all__ = [
    "ACCEPTANCE_RISK_REASONS",
    "EVIDENCE_NOT_LINKED",
    "EVIDENCE_SELF_ASSERTED_ONLY",
    "ITEM_NEVER_ATTEMPTED",
    "acceptance_risk",
]

ITEM_NEVER_ATTEMPTED: Final = "requested_item_never_attempted"
EVIDENCE_NOT_LINKED: Final = "evidence_not_linked_to_declared_items"
EVIDENCE_SELF_ASSERTED_ONLY: Final = "evidence_self_asserted_only"
ACCEPTANCE_RISK_REASONS: Final = (
    ITEM_NEVER_ATTEMPTED,
    EVIDENCE_NOT_LINKED,
    EVIDENCE_SELF_ASSERTED_ONLY,
)
# Digest provenance FinishUP itself established: the bytes came from an approved check, an import
# report or the observation path, not from the agent's assertion.
_CORROBORATING_PROVENANCE: Final = frozenset(
    {
        EvidenceDigestProvenance.APPROVED_CHECK,
        EvidenceDigestProvenance.IMPORT_OBSERVED,
        EvidenceDigestProvenance.OBSERVATION_CAPTURED,
    }
)


def _item_attempted(
    item: RequestedItem, attempted: frozenset[str], matched_commands: frozenset[str]
) -> bool:
    """The ``requested_item_never_attempted`` rule's attempt test (work-integrity, ADR-045)."""

    if item.value in attempted:
        return True
    if item.item_kind is RequestedItemKind.COMMAND:
        return item.value in matched_commands
    if item.item_kind in {RequestedItemKind.FILE, RequestedItemKind.DIRECTORY}:
        return value_in_attempted(item.value, attempted)
    return False


def _corroborated(
    projection: ProjectionState,
    records_by_event: Mapping[EventId, LedgerRecord],
    observed_events: frozenset[EventId],
    ref: str,
    source_events: Iterable[EventId],
) -> bool:
    """Whether FinishUP, not only the agent, stands behind one cited resolution reference."""

    if any(event in observed_events for event in source_events):
        return True
    if ref.startswith("res_"):
        result = projection.results.get(ResultId(ref))
        return result is not None and result.source_event_id in observed_events
    evidence = projection.evidence.get(EvidenceId(ref))
    if evidence is None:
        return False
    record = records_by_event.get(evidence.source_event_id)
    if record is not None and is_observation_authored(record):
        return True
    payload: EvidenceRecordedPayload | None = evidence.payload
    binding = None if payload is None else payload.digest_binding
    return binding is not None and binding.provenance in _CORROBORATING_PROVENANCE


@dataclass(frozen=True, slots=True)
class _ReadIndex:
    """What every resolved obligation's classification reads, built once per read (check D3).

    A status read classifies every resolved obligation; per-obligation scans of the action,
    result and record inventories made that quadratic in a long task.
    """

    records_by_event: Mapping[EventId, LedgerRecord]
    observed_events: frozenset[EventId]
    matched_commands: frozenset[str]
    evidence_actions: Mapping[str, tuple[ActionId, ...]]
    global_attempted: frozenset[str]
    attempted_by_obligation: Mapping[ObligationId, frozenset[str]]
    # Each cited reference's source actions, resolved once for the whole read (check D3-R2).
    source_cache: dict[str, tuple[tuple[ActionRecordedPayload, EventId], ...]]


def _read_index(projection: ProjectionState, records: tuple[LedgerRecord, ...]) -> _ReadIndex:
    observed_events = observed_event_ids_from_records(records)
    command_values = {
        item.value
        for record in projection.obligations.values()
        if record.payload is not None
        for item in record.payload.requested_items
        if item.item_kind is RequestedItemKind.COMMAND
    }
    matched_commands: frozenset[str] = (
        observed_planned_commands(
            projection,
            observed_events,
            cooperative_event_ids_from_records(records),
            command_values,
        )
        if command_values
        else frozenset()
    )
    # ``attempted_items_for_obligation``'s rule, in one pass: an action naming no obligation
    # covers every obligation; one that names obligations covers exactly those.
    global_attempted: set[str] = set()
    by_obligation: dict[ObligationId, set[str]] = {}
    for action in projection.actions.values():
        payload = action.payload
        if payload is None or not payload.attempted_items:
            continue
        if not payload.obligation_refs:
            global_attempted.update(payload.attempted_items)
            continue
        for obligation in payload.obligation_refs:
            by_obligation.setdefault(obligation, set()).update(payload.attempted_items)
    return _ReadIndex(
        {record.event_id: record for record in records},
        observed_events,
        matched_commands,
        results_by_evidence(projection),
        frozenset(global_attempted),
        {key: frozenset(value) for key, value in by_obligation.items()},
        {},
    )


def _reasons(
    projection: ProjectionState,
    records: tuple[LedgerRecord, ...],
    index: _ReadIndex,
    obligation: ObligationId,
    payload: ObligationPublishedPayload,
) -> tuple[str, ...]:
    reasons: list[str] = []
    attempted = index.global_attempted | index.attempted_by_obligation.get(obligation, frozenset())
    if any(
        not _item_attempted(item, attempted, index.matched_commands)
        for item in payload.requested_items
        if item.role is not RequestedItemRole.INPUT
    ):
        reasons.append(ITEM_NEVER_ATTEMPTED)
    declared = declared_items(payload)
    sources = evidence_sources(
        projection,
        index.records_by_event,
        index.observed_events,
        payload,
        index.evidence_actions,
        index.source_cache,
    )
    if declared and alignment_of(declared, sources) in {
        "evidence_off_declared_items",
        "evidence_unattributed",
    }:
        reasons.append(EVIDENCE_NOT_LINKED)
    corroborated = any(
        _corroborated(
            projection,
            index.records_by_event,
            index.observed_events,
            source.ref,
            (event for _action, event in source.actions),
        )
        for source in sources
    ) or (
        # Only an obligation that requests a command can have a matching observed attempt.
        any(item.item_kind is RequestedItemKind.COMMAND for item in payload.requested_items)
        and any(
            attempt.relation == "matching_observed_attempt"
            for attempt in command_attempts(projection, records, obligation)
        )
    )
    if not corroborated:
        reasons.append(EVIDENCE_SELF_ASSERTED_ONLY)
    return tuple(reasons)


# One entry: the last read's inputs and answer. Status may derive readiness more than once for one
# projection and prefix (compact plus an enrichment); both are immutable, and holding them keeps
# their identities from being reused while the entry stands.
_MEMO: list[
    tuple[
        ProjectionState,
        tuple[LedgerRecord, ...],
        tuple[ObligationId, ...],
        int,
        tuple[tuple[ObligationId, tuple[str, ...]], ...],
    ]
] = []


def acceptance_risk(
    projection: ProjectionState,
    records: tuple[LedgerRecord, ...],
    resolved: Iterable[ObligationId],
) -> tuple[tuple[ObligationId, tuple[str, ...]], ...]:
    """``(obligation, reasons)`` for each *resolved* obligation the ledger flags, in id order.

    ``resolved`` is the closure verdict's resolved set (basis ``resolved``); an obligation whose
    payload is unreadable is flagged with every reason (fail closed: it bounds the receipt). The
    inventories are indexed once per call, and an identical call is answered from memory.
    """

    ordered = tuple(sorted(set(resolved), key=lambda value: str(value).encode()))
    generation = command_identity_key_generation()
    if _MEMO:
        memo_projection, memo_records, memo_resolved, memo_generation, memo_answer = _MEMO[0]
        if (
            memo_projection is projection
            and memo_records is records
            and memo_resolved == ordered
            and memo_generation == generation
        ):
            return memo_answer
    flagged: list[tuple[ObligationId, tuple[str, ...]]] = []
    index: _ReadIndex | None = None
    for obligation in ordered:
        record = projection.obligations.get(obligation)
        payload = None if record is None else record.payload
        if payload is None:
            flagged.append((obligation, ACCEPTANCE_RISK_REASONS))
            continue
        if index is None:
            index = _read_index(projection, records)
        reasons = _reasons(projection, records, index, obligation, payload)
        if reasons:
            flagged.append((obligation, reasons))
    answer = tuple(flagged)
    _MEMO[:] = [(projection, records, ordered, generation, answer)]
    return answer
