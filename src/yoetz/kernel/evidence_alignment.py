"""Where an obligation's resolution evidence came from, beside what it declared (ADR-047, ADR-033).

The inspection check (``application.check_inspection``, item 3) and the Stop gate's acceptance risk
(``kernel.acceptance_risk``, tb4n5 #1050) read one classification: for each cited result or
evidence item, the action behind it (hook-observed or agent-asserted) by recorded link only, and
which declared deliverables or requested commands that action names (its ``attempted_items`` and,
for a requested command, the shared run matcher of ADR-045). Yoetz reads no working directory,
environment or service configuration, so this compares only what the record links.

Pure and replay-derived; every value is an id, an index or a closed token.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal

from yoetz.domain.events import (
    ActionRecordedPayload,
    LedgerRecord,
    ObligationPublishedPayload,
    RequestedItemKind,
    RequestedItemRole,
)
from yoetz.domain.values import ActionId, EventId, EvidenceId, ResultId
from yoetz.kernel.command_attempts import value_in_attempted
from yoetz.kernel.projections import ProjectionState
from yoetz.kernel.task_facts import (
    observed_run_from_command,
    planned_match,
    requested_planned_command,
)

__all__ = [
    "MAX_ALIGNMENT_ROWS",
    "Alignment",
    "EvidenceSource",
    "SourceOrigin",
    "alignment_of",
    "declared_items",
    "evidence_sources",
    "results_by_evidence",
    "source_actions",
]

MAX_ALIGNMENT_ROWS: Final = 64
_DECLARED_PATH_KINDS: Final = frozenset({RequestedItemKind.FILE, RequestedItemKind.DIRECTORY})

type SourceOrigin = Literal["observed", "asserted", "unattributed"]
type Alignment = Literal[
    "no_declared_items",
    "evidence_names_declared_item",
    "evidence_off_declared_items",
    "evidence_unattributed",
]


@dataclass(frozen=True, slots=True)
class EvidenceSource:
    """One cited resolution reference and the recorded actions behind it."""

    ref: str
    origin: SourceOrigin
    named: frozenset[int]
    actions: tuple[tuple[ActionRecordedPayload, EventId], ...]


def declared_items(payload: ObligationPublishedPayload) -> list[tuple[int, str]]:
    """``(index, item kind)`` of each requested command and each non-input file or directory."""

    declared: list[tuple[int, str]] = []
    for index, item in enumerate(payload.requested_items):
        if item.item_kind is RequestedItemKind.COMMAND or (
            item.item_kind in _DECLARED_PATH_KINDS and item.role is not RequestedItemRole.INPUT
        ):
            declared.append((index, item.item_kind.value))
    return declared[:MAX_ALIGNMENT_ROWS]


def _named_indexes(
    payload: ObligationPublishedPayload,
    declared: list[tuple[int, str]],
    action: ActionRecordedPayload,
    *,
    observed: bool,
) -> set[int]:
    """Declared items the action behind a piece of evidence names, through recorded links only."""

    named: set[int] = set()
    for index, _kind in declared:
        item = payload.requested_items[index]
        if value_in_attempted(item.value, action.attempted_items):
            named.add(index)
            continue
        if item.item_kind is not RequestedItemKind.COMMAND or action.command is None:
            continue
        if observed:
            run = observed_run_from_command(action.command)
            planned = requested_planned_command(item.value)
            if run is not None and planned is not None and planned_match(run, planned) is not None:
                named.add(index)
        elif action.command == item.value:
            named.add(index)
    return named


def results_by_evidence(projection: ProjectionState) -> Mapping[str, tuple[ActionId, ...]]:
    """``evidence id -> the actions of the results citing it``, in result-id order.

    Built once per read: resolving every cited evidence id against the whole result inventory
    made a status read quadratic in long tasks (tb4n5 check D3).
    """

    index: dict[str, list[ActionId]] = {}
    for result_id in sorted(projection.results, key=lambda value: str(value).encode()):
        result = projection.results[result_id]
        if result.payload is None:
            continue
        for ref in result.payload.evidence_refs:
            index.setdefault(str(ref), []).append(result.payload.action_id)
    return {key: tuple(value) for key, value in index.items()}


def source_actions(
    projection: ProjectionState,
    records_by_event: Mapping[EventId, LedgerRecord],
    ref: str,
    evidence_actions: Mapping[str, tuple[ActionId, ...]] | None = None,
    source_cache: dict[str, tuple[tuple[ActionRecordedPayload, EventId], ...]] | None = None,
) -> tuple[tuple[ActionRecordedPayload, EventId], ...]:
    """The actions a cited result or evidence item came from, by recorded link.

    ``evidence_actions`` is ``results_by_evidence(projection)`` when the caller resolves many
    references against one projection; without it the inventory is scanned for this one.
    ``source_cache`` holds each reference's answer for one read, so a reference many obligations
    cite is resolved once (tb4n5 check D3-R2: 200 obligations sharing one evidence item behind
    1,000 results rebuilt the same tuple 200 times).
    """

    if source_cache is not None:
        cached = source_cache.get(ref)
        if cached is not None:
            return cached
    actions: list[tuple[ActionRecordedPayload, EventId]] = []
    # An action id names one projection row, so its identity is the deduplication key; comparing
    # payload pairs made a reference with many linked actions quadratic.
    seen: set[ActionId] = set()

    def add(action_id: ActionId) -> None:
        if action_id in seen:
            return
        record = projection.actions.get(action_id)
        if record is not None and record.payload is not None:
            seen.add(action_id)
            actions.append((record.payload, record.source_event_id))

    if ref.startswith("res_"):
        result = projection.results.get(ResultId(ref))
        if result is not None and result.payload is not None:
            add(result.payload.action_id)
        answer = tuple(actions)
        if source_cache is not None:
            source_cache[ref] = answer
        return answer
    if evidence_actions is None:
        evidence_actions = results_by_evidence(projection)
    for action_id in evidence_actions.get(ref, ()):
        add(action_id)
    evidence = projection.evidence.get(EvidenceId(ref))
    if evidence is not None:
        source = records_by_event.get(evidence.source_event_id)
        for parent in () if source is None else source.causal_parents:
            parent_record = records_by_event.get(parent)
            if (
                parent_record is not None
                and parent_record.schema.name == "action_recorded"
                and type(parent_record.payload) is ActionRecordedPayload
            ):
                add(parent_record.payload.action_id)
    answer = tuple(actions)
    if source_cache is not None:
        source_cache[ref] = answer
    return answer


def evidence_sources(
    projection: ProjectionState,
    records_by_event: Mapping[EventId, LedgerRecord],
    observed_events: frozenset[EventId],
    payload: ObligationPublishedPayload,
    evidence_actions: Mapping[str, tuple[ActionId, ...]] | None = None,
    source_cache: dict[str, tuple[tuple[ActionRecordedPayload, EventId], ...]] | None = None,
) -> tuple[EvidenceSource, ...]:
    """Each cited resolution reference (at most 64), its origin and the declared items it names."""

    declared = declared_items(payload)
    if evidence_actions is None:
        evidence_actions = results_by_evidence(projection)
    sources: list[EvidenceSource] = []
    for ref in tuple(payload.resolution_evidence_refs)[:MAX_ALIGNMENT_ROWS]:
        actions = source_actions(
            projection, records_by_event, str(ref), evidence_actions, source_cache
        )
        named: set[int] = set()
        origin: SourceOrigin = "unattributed"
        for action, source_event in actions:
            observed = source_event in observed_events
            named |= _named_indexes(payload, declared, action, observed=observed)
            if observed:
                origin = "observed"
            elif origin == "unattributed":
                origin = "asserted"
        sources.append(EvidenceSource(str(ref), origin, frozenset(named), actions))
    return tuple(sources)


def alignment_of(declared: list[tuple[int, str]], sources: tuple[EvidenceSource, ...]) -> Alignment:
    """The obligation's alignment token from its declared items and its cited sources."""

    if not declared:
        return "no_declared_items"
    if any(source.named for source in sources):
        return "evidence_names_declared_item"
    if any(source.actions for source in sources):
        return "evidence_off_declared_items"
    return "evidence_unattributed"
