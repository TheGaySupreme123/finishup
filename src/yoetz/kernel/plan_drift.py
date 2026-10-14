"""Drift signals for plans that no longer describe the work.

The signals in this module are intentionally derived from recorded frontiers and explicit
relations.  They never inspect plan prose, action descriptions, or the user's request looking
for similar words.  A signal is therefore a bounded diagnostic: it says that the ledger lacks a
relation needed to read the plan as current, not that the work is incomplete.

``plan_unrefined_before_first_edit`` and ``obligation_evidence_stale_after_scope_edit`` stay
advisory.  ``instruction_requirement_unmapped`` is agent-actionable (TB4 pilot, 2026-10-05):
when a task statement is recorded and the effective plan declares obligations, none of which
cites a statement event in ``source_refs``, or a completion claim stands on no plan or an
explicit empty scope without a recorded no-material-work decision, the agent has not decomposed
the user's request into the plan.  Yoetz checks only that structural link; the agent does the
extraction.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Final, cast

from yoetz.domain.events import (
    AcceptedEvent,
    ActionKind,
    ActionRecordedPayload,
    DecisionRecordedPayload,
    LedgerRecord,
    ObligationStatus,
    PlanPublishedPayload,
    PlanRevisedPayload,
)
from yoetz.domain.task_statement import (
    NO_MATERIAL_WORK_MARKER,
    RecordedTaskStatement,
    current_task_statement,
)
from yoetz.domain.values import EventId, EvidenceId, ObligationId, ResultId
from yoetz.kernel.claims import completion_claim_present
from yoetz.kernel.plan_scope import current_plan_scope
from yoetz.kernel.projections import PlanProjectionRecord, ProjectionState

__all__ = [
    "INSTRUCTION_REQUIREMENT_UNMAPPED_GAP",
    "OBLIGATION_EVIDENCE_STALE_AFTER_SCOPE_EDIT_GAP",
    "PLAN_DRIFT_ADVISORY_GAPS",
    "PLAN_DRIFT_GAPS",
    "PLAN_UNREFINED_BEFORE_FIRST_EDIT_GAP",
    "PlanDriftSignals",
    "no_material_work_decided",
    "plan_drift_signals",
    "stale_resolved_obligations",
    "statement_mapped_by",
    "task_statement_scope_empty_at_completion",
    "task_statement_unmapped",
]


# Every plan drift code stays visible in status/check and receipt text.  Only the advisory subset
# below is excluded from completion verdicts and closure blockers; an unmapped task statement is
# agent work (the work-integrity pack raises a finding for it) and bounds completion coverage.
PLAN_UNREFINED_BEFORE_FIRST_EDIT_GAP: Final = "plan_unrefined_before_first_edit"
OBLIGATION_EVIDENCE_STALE_AFTER_SCOPE_EDIT_GAP: Final = "obligation_evidence_stale_after_scope_edit"
INSTRUCTION_REQUIREMENT_UNMAPPED_GAP: Final = "instruction_requirement_unmapped"
PLAN_DRIFT_GAPS: Final = frozenset(
    {
        PLAN_UNREFINED_BEFORE_FIRST_EDIT_GAP,
        OBLIGATION_EVIDENCE_STALE_AFTER_SCOPE_EDIT_GAP,
        INSTRUCTION_REQUIREMENT_UNMAPPED_GAP,
    }
)
PLAN_DRIFT_ADVISORY_GAPS: Final = PLAN_DRIFT_GAPS - {INSTRUCTION_REQUIREMENT_UNMAPPED_GAP}


@dataclass(frozen=True, slots=True)
class PlanDriftSignals:
    """Closed, deterministic plan drift facts for one accepted prefix."""

    codes: tuple[str, ...] = ()
    stale_obligation_ids: tuple[ObligationId, ...] = ()

    def __post_init__(self) -> None:
        if type(self.codes) is not tuple or self.codes != tuple(
            sorted(set(self.codes), key=str.encode)
        ):
            raise ValueError("plan_drift_signals_invalid")
        if not set(self.codes) <= PLAN_DRIFT_GAPS:
            raise ValueError("plan_drift_signals_invalid")
        if type(self.stale_obligation_ids) is not tuple or self.stale_obligation_ids != tuple(
            sorted(set(self.stale_obligation_ids), key=str.encode)
        ):
            raise ValueError("plan_drift_signals_invalid")
        if bool(self.stale_obligation_ids) != (
            OBLIGATION_EVIDENCE_STALE_AFTER_SCOPE_EDIT_GAP in self.codes
        ):
            raise ValueError("plan_drift_signals_invalid")

    @property
    def present(self) -> bool:
        return bool(self.codes)


def _ordered_records(records: Iterable[LedgerRecord]) -> tuple[LedgerRecord, ...]:
    return tuple(sorted(records, key=lambda row: row.ledger.ingestion_sequence))


def _first_material_edit(records: tuple[LedgerRecord, ...]) -> int | None:
    frontiers = [
        record.ledger.ingestion_sequence
        for record in records
        if type(record) is AcceptedEvent
        and type(record.payload) is ActionRecordedPayload
        and record.payload.action_kind is ActionKind.EDIT
    ]
    return min(frontiers, default=None)


def _plan_unrefined_before_edit(
    plans: Mapping[int, PlanProjectionRecord], first_edit_frontier: int | None
) -> bool:
    if first_edit_frontier is None:
        return False
    ordered = tuple(
        sorted(
            (
                record
                for record in plans.values()
                if type(getattr(record, "payload", None))
                in {PlanPublishedPayload, PlanRevisedPayload}
            ),
            key=lambda record: (
                record.source_frontier,
                str(record.source_event_id).encode("ascii"),
            ),
        )
    )
    if not ordered:
        return False
    before_edit = tuple(
        record for record in ordered if record.source_frontier <= first_edit_frontier
    )
    if not before_edit:
        # A plan published only after the first edit cannot establish this particular timing gap.
        return False
    initial = before_edit[0]
    # A later valid revision repairs the stale-plan condition even when the agent refined only
    # after its first edit.  A later full ``plan_published`` restatement is not the required
    # refinement: it has no carried/superseded/waived obligation relation, so it must not clear
    # the signal merely by replacing the effective scope.
    return not any(
        type(getattr(record, "payload", None)) is PlanRevisedPayload
        and record.source_frontier > initial.source_frontier
        for record in ordered[1:]
    )


def _reference_frontier(
    reference: EvidenceId | ResultId,
    projection: ProjectionState,
) -> int | None:
    if reference.startswith("evd_"):
        row = projection.evidence.get(EvidenceId(str(reference)))
    elif reference.startswith("res_"):
        row = projection.results.get(ResultId(str(reference)))
    else:  # The payload validator should make this unreachable.
        return None
    return None if row is None or row.payload is None else row.source_frontier


def _record_edits(
    records: tuple[LedgerRecord, ...],
) -> Iterable[tuple[int, ActionRecordedPayload]]:
    for record in records:
        if (
            type(record) is AcceptedEvent
            and type(record.payload) is ActionRecordedPayload
            and record.payload.action_kind is ActionKind.EDIT
        ):
            yield record.ledger.ingestion_sequence, record.payload


def _projection_edits(projection: ProjectionState) -> Iterable[tuple[int, ActionRecordedPayload]]:
    for row in projection.actions.values():
        if row.payload is not None and row.payload.action_kind is ActionKind.EDIT:
            yield row.source_frontier, row.payload


def stale_resolved_obligations(projection: ProjectionState) -> tuple[ObligationId, ...]:
    """The resolved obligations whose every resolution reference predates a later edit.

    Read from the projection alone (each action at its latest recorded frontier, which can only
    make an obligation look staler), so a historical proof state can name exactly which
    obligations ``obligation_evidence_stale_after_scope_edit`` is about.
    """

    return _stale_obligations(projection, _projection_edits(projection))


def _stale_obligations(
    projection: ProjectionState,
    edits: Iterable[tuple[int, ActionRecordedPayload]],
) -> tuple[ObligationId, ...]:
    scope = current_plan_scope(projection.plans, projection.coverage_gaps)
    if not scope.readable or scope.effective_obligation_refs is None:
        return ()
    edits_by_obligation: dict[ObligationId, int] = {}
    unscoped_edit_frontier: int | None = None
    for frontier, payload in edits:
        if not payload.obligation_refs:
            unscoped_edit_frontier = max(unscoped_edit_frontier or 0, frontier)
            continue
        for obligation in payload.obligation_refs:
            edits_by_obligation[obligation] = max(edits_by_obligation.get(obligation, 0), frontier)

    stale: list[ObligationId] = []
    for obligation in scope.effective_obligation_refs:
        row = projection.obligations.get(obligation)
        payload = None if row is None else row.payload
        if payload is None or payload.status is not ObligationStatus.RESOLVED:
            continue
        if not payload.resolution_evidence_refs:
            continue
        scoped_edit_frontier = edits_by_obligation.get(obligation)
        if scoped_edit_frontier is None:
            edit_frontier = unscoped_edit_frontier
        elif unscoped_edit_frontier is None:
            edit_frontier = scoped_edit_frontier
        else:
            # A global edit applies to every obligation even when an earlier scoped edit also
            # exists.  Use the latest frontier so a later global change cannot be hidden by the
            # first obligation-specific edit.
            edit_frontier = max(scoped_edit_frontier, unscoped_edit_frontier)
        if edit_frontier is None:
            continue
        evidence_frontiers = tuple(
            frontier
            for reference in payload.resolution_evidence_refs
            if (frontier := _reference_frontier(reference, projection)) is not None
        )
        # Unknown evidence remains a separate ledger coverage problem.  This signal only claims
        # staleness when every retained resolution reference is readable and predates the edit.
        if (
            len(evidence_frontiers) == len(payload.resolution_evidence_refs)
            and evidence_frontiers
            and max(evidence_frontiers) < edit_frontier
        ):
            stale.append(obligation)
    return tuple(sorted(set(stale), key=str.encode))


def _statement_events(
    statement: RecordedTaskStatement | EventId | Iterable[EventId] | None,
) -> frozenset[EventId]:
    if statement is None:
        return frozenset()
    if type(statement) is RecordedTaskStatement:
        return frozenset(statement.equivalent_event_ids)
    if isinstance(statement, str):
        return frozenset({EventId(statement)})
    return frozenset(cast(Iterable[EventId], statement))


def statement_mapped_by(
    projection: ProjectionState,
    statement: RecordedTaskStatement | EventId | Iterable[EventId] | None,
) -> bool:
    """Whether an effective obligation cites the statement (any digest-equivalent event)."""

    events = _statement_events(statement)
    scope = current_plan_scope(projection.plans, projection.coverage_gaps)
    if not events or not scope.readable or not scope.effective_obligation_refs:
        return False
    return any(
        row.payload is not None and not events.isdisjoint(row.payload.source_refs)
        for obligation in scope.effective_obligation_refs
        if (row := projection.obligations.get(obligation)) is not None
    )


def task_statement_unmapped(
    projection: ProjectionState,
    statement: RecordedTaskStatement | EventId | Iterable[EventId] | None,
) -> bool:
    """True when a statement exists and no effective obligation cites it.

    The relation is exact: an obligation maps the statement only when its ``source_refs`` names
    an event that recorded the current statement content. A re-attach or plan event that repeats
    the unchanged statement is the same request, so citing any of those events counts; an amended
    statement has a different digest and must be mapped again. No statement, an unreadable or
    absent plan, and an explicit empty-scope declaration never report this condition; the
    completion-time rule below covers the last two.
    """

    events = _statement_events(statement)
    scope = current_plan_scope(projection.plans, projection.coverage_gaps)
    if not events or not scope.readable or scope.effective_obligation_refs is None:
        return False
    if not scope.effective_obligation_refs:
        return False
    return not statement_mapped_by(projection, events)


def no_material_work_decided(
    projection: ProjectionState,
    statement: RecordedTaskStatement | EventId | Iterable[EventId] | None,
    *,
    workspace_changed: bool | None,
) -> bool:
    """Whether a readable decision records that the request asks for no material work.

    The decision's statement must hold the exact line ``yoetz-no-material-work:<event>`` naming an
    event that recorded the current statement content; its rationale is required by the schema.
    The decision is contradicted, and therefore never counts, while the task records any edit
    action or ``workspace_changed`` is not ``False``: hosts record shell writes as command actions,
    so the check-time change capture is the structural witness that no file changed. ``True``
    (the capture shows a changed path) and ``None`` (no capture was available) both fail closed.
    """

    events = _statement_events(statement)
    if not events or workspace_changed is not False:
        return False
    if any(
        row.payload is not None and row.payload.action_kind is ActionKind.EDIT
        for row in projection.actions.values()
    ):
        return False
    markers = {f"{NO_MATERIAL_WORK_MARKER}:{event}" for event in events}
    for row in projection.decisions.values():
        payload = getattr(row, "payload", None)
        if (
            type(payload) is not DecisionRecordedPayload
            or getattr(row, "superseded_by_event_id", None) is not None
        ):
            # A superseded decision is no longer the agent's recorded position.
            continue
        if any(line.strip() in markers for line in payload.statement.splitlines()):
            return True
    return False


def task_statement_scope_empty_at_completion(
    projection: ProjectionState,
    statement: RecordedTaskStatement | EventId | Iterable[EventId] | None,
    *,
    workspace_changed: bool | None,
) -> bool:
    """True when a completion claim stands on no plan or an explicit empty scope.

    A recorded statement, an effective completion claim, and a readable plan chain that declares
    no obligation (no plan at all, or an explicit empty-scope declaration) mean the agent is
    claiming completion without decomposing the user's request. Mid-task checks before any
    completion claim never report it. A recorded no-material-work decision answers it only when
    ``workspace_changed`` is ``False`` (see ``no_material_work_decided``).
    """

    events = _statement_events(statement)
    scope = current_plan_scope(projection.plans, projection.coverage_gaps)
    if not events or not scope.readable:
        return False
    if scope.has_plan and scope.effective_obligation_refs:
        return False
    if not completion_claim_present(projection):
        return False
    return not no_material_work_decided(projection, events, workspace_changed=workspace_changed)


def _instruction_unmapped(projection: ProjectionState, records: tuple[LedgerRecord, ...]) -> bool:
    # This advisory drift code is derived from the ledger prefix alone, where no check-time change
    # capture exists. It keeps the edit-action rule only (``workspace_changed=False``); the
    # completion-gating finding in the check path consults the capture and fails closed.
    statement = current_task_statement(records)
    return task_statement_unmapped(projection, statement) or (
        task_statement_scope_empty_at_completion(projection, statement, workspace_changed=False)
    )


def plan_drift_signals(
    projection: ProjectionState,
    records: Iterable[LedgerRecord],
) -> PlanDriftSignals:
    """Derive plan drift signals from exact ledger relations.

    A caller must pass the same accepted prefix that produced ``projection``.  The helper is
    deliberately total for a readable projection and ignores unknown/redacted payloads rather
    than treating them as evidence of drift.
    """

    if type(projection) is not ProjectionState:
        raise TypeError("plan_drift_projection_invalid")
    ordered = _ordered_records(records)
    first_edit = _first_material_edit(ordered)
    codes: set[str] = set()
    plan_scope = current_plan_scope(projection.plans, projection.coverage_gaps)
    if plan_scope.readable and _plan_unrefined_before_edit(projection.plans, first_edit):
        codes.add(PLAN_UNREFINED_BEFORE_FIRST_EDIT_GAP)
    stale = _stale_obligations(projection, _record_edits(ordered))
    if stale:
        codes.add(OBLIGATION_EVIDENCE_STALE_AFTER_SCOPE_EDIT_GAP)
    if _instruction_unmapped(projection, ordered):
        codes.add(INSTRUCTION_REQUIREMENT_UNMAPPED_GAP)
    return PlanDriftSignals(tuple(sorted(codes, key=str.encode)), stale)
