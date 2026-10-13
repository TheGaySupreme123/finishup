"""Which resolved obligations the ledger flags as risky to call met (tb4n5, issue #1050, ADR-033).

The Stop gate's acceptance re-read (A-12) asks the agent to read each resolved obligation's
``acceptance_criteria`` against its final output, so an outcome that is infeasible, skipped or
partial is downgraded to ``acknowledged_not_done`` (or disclosed as a verification limit) instead
of standing as resolved. tb4n4 asked it for every resolved obligation; #1050 then suppressed it when
the final message restated two thirds of a criterion's words, which no real final message did
(tb4n5: 18 of 18 attempts asked, 1 of 110 obligations covered). The owner's rule (2026-10-13): ask
only for the obligations whose recorded resolution the ledger itself flags, from facts the record
already holds:

* ``requested_item_never_attempted``: an output, command or other non-input item the obligation
  requested has no attempt (no ``attempted_items`` entry in any spelling, and, for a command, no
  hook-observed run matching it, ADR-045);
* ``evidence_not_linked_to_declared_items``: the obligation declares deliverables or commands, and
  no cited resolution evidence traces through a recorded link to an action that names one
  (``kernel.evidence_alignment``: the inspection's ``evidence_off_declared_items`` or
  ``evidence_unattributed``);
* ``evidence_self_asserted_only``: no cited resolution reference is corroborated by Yoetz (a
  hook-observed run or its result, observation-captured evidence, an approved check or an import
  report), and no requested command item has a matching observed run linked to it.

Pure and replay-derived over one projection and its record prefix; nothing is stored, and a ledger
replays to the same set after a restart, a reattach or an upgrade. Every value is an id or a closed
reason token.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

from yoetz.domain.events import (
    EvidenceDigestProvenance,
    EvidenceRecordedPayload,
    LedgerRecord,
    ObligationPublishedPayload,
    RequestedItem,
    RequestedItemKind,
    RequestedItemRole,
    is_observation_authored,
)
from yoetz.domain.values import EventId, EvidenceId, ObligationId, ResultId
from yoetz.kernel.command_attempts import (
    attempted_items_for_obligation,
    command_attempts,
    value_in_attempted,
)
from yoetz.kernel.evidence_alignment import alignment_of, declared_items, evidence_sources
from yoetz.kernel.observed_failures import observed_event_ids_from_records
from yoetz.kernel.projections import ProjectionState
from yoetz.kernel.task_facts import cooperative_event_ids_from_records, observed_planned_commands

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
# Digest provenance Yoetz itself established: the bytes came from an approved check, an import
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
    records_by_event: dict[EventId, LedgerRecord],
    observed_events: frozenset[EventId],
    ref: str,
    source_events: Iterable[EventId],
) -> bool:
    """Whether Yoetz, not only the agent, stands behind one cited resolution reference."""

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


def _reasons(
    projection: ProjectionState,
    records: tuple[LedgerRecord, ...],
    records_by_event: dict[EventId, LedgerRecord],
    observed_events: frozenset[EventId],
    matched_commands: frozenset[str],
    obligation: ObligationId,
    payload: ObligationPublishedPayload,
) -> tuple[str, ...]:
    reasons: list[str] = []
    attempted = attempted_items_for_obligation(projection, obligation)
    if any(
        not _item_attempted(item, attempted, matched_commands)
        for item in payload.requested_items
        if item.role is not RequestedItemRole.INPUT
    ):
        reasons.append(ITEM_NEVER_ATTEMPTED)
    declared = declared_items(payload)
    sources = evidence_sources(projection, records_by_event, observed_events, payload)
    if declared and alignment_of(declared, sources) in {
        "evidence_off_declared_items",
        "evidence_unattributed",
    }:
        reasons.append(EVIDENCE_NOT_LINKED)
    corroborated = any(
        _corroborated(
            projection,
            records_by_event,
            observed_events,
            source.ref,
            (event for _action, event in source.actions),
        )
        for source in sources
    ) or any(
        attempt.relation == "matching_observed_attempt"
        for attempt in command_attempts(projection, records, obligation)
    )
    if not corroborated:
        reasons.append(EVIDENCE_SELF_ASSERTED_ONLY)
    return tuple(reasons)


def acceptance_risk(
    projection: ProjectionState,
    records: tuple[LedgerRecord, ...],
    resolved: Iterable[ObligationId],
) -> tuple[tuple[ObligationId, tuple[str, ...]], ...]:
    """``(obligation, reasons)`` for each *resolved* obligation the ledger flags, in id order.

    ``resolved`` is the closure verdict's resolved set (basis ``resolved``); an obligation whose
    payload is unreadable is flagged with every reason (fail closed: the re-read is asked).
    """

    observed_events = observed_event_ids_from_records(records)
    records_by_event = {record.event_id: record for record in records}
    command_values = {
        item.value
        for record in projection.obligations.values()
        if record.payload is not None
        for item in record.payload.requested_items
        if item.item_kind is RequestedItemKind.COMMAND
    }
    matched_commands = observed_planned_commands(
        projection,
        observed_events,
        cooperative_event_ids_from_records(records),
        command_values,
    )
    flagged: list[tuple[ObligationId, tuple[str, ...]]] = []
    for obligation in sorted(set(resolved), key=lambda value: str(value).encode()):
        record = projection.obligations.get(obligation)
        payload = None if record is None else record.payload
        if payload is None:
            flagged.append((obligation, ACCEPTANCE_RISK_REASONS))
            continue
        reasons = _reasons(
            projection,
            records,
            records_by_event,
            observed_events,
            matched_commands,
            obligation,
            payload,
        )
        if reasons:
            flagged.append((obligation, reasons))
    return tuple(flagged)
