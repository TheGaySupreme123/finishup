"""The read-only ``mode: inspect`` check: what is left to close and why (issue #1048, ADR-047).

An inspection answers three questions from the record the service already holds, at the current
frontier, in one call:

1. **What is left** (``remaining``): the closure verdict status prints (ADR-046) - the readiness
   split into the agent's gaps and the standing limitations FinishUP itself carries (observation,
   capture, review, route), the predicted receipt conclusion, and every unresolved obligation and
   finding with its class and basis. An agent-work obligation names what it still lacks and whose
   move that is: the agent's (an unattempted requested item, no resolution evidence, an asserted
   command whose observed run differs, an unconfirmed blocker) or FinishUP's (an asserted command
   run no hook observation links to).
2. **What the hooks observed since the last check** (``observed_since_check``): every
   hook-observed action after the last recorded check, classed by ``later_material`` with its
   tool, write class, outcome, exit status and keyed command commitment. FinishUP's own calls and
   host bookkeeping are left out; they never change the work.
3. **Whether the evidence matches the declared setup** (``evidence_alignment``): for each
   obligation that cites resolution evidence, the action behind every cited result or evidence
   item (hook-observed or agent-asserted), its keyed command commitment, and which declared
   deliverables or requested commands it names, through recorded links only (the action's
   ``attempted_items`` and, for a requested command, the shared run matcher of ADR-045).

It is a read like ``status``: it records nothing, mints no findings, calls no reviewer and
egresses nothing, so it has no operation record and a lost response is answered by asking again.
Every value is structural (ids, closed tokens, counts, requested-item indexes, keyed commitments);
no command text, path or prose leaves the service.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Final, Literal, Protocol, cast

from finishup.application.closure_basis import load_closure_basis
from finishup.application.status import Application as StatusApplication
from finishup.application.status import current_closure_readiness
from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    LedgerRecord,
    ObligationPublishedPayload,
    ObligationStatus,
    RequestedItemKind,
    RequestedItemRole,
    is_observation_authored,
)
from finishup.domain.values import ActionId, EventId, EvidenceId, Frontier, ResultId
from finishup.kernel.closure_class import (
    FindingClosure,
    FindingClosureClass,
    ObligationClosure,
    ObligationClosureClass,
)
from finishup.kernel.command_attempts import (
    attempted_items_for_obligation,
    command_attempts,
    value_in_attempted,
)
from finishup.kernel.later_material import (
    LaterMaterialClass,
    classify_later_material,
    observed_actions_by_event,
    supersession_exempt,
)
from finishup.kernel.observed_failures import (
    command_identity,
    observed_action_runtime_tokens,
    observed_action_tool,
    observed_event_ids_from_records,
)
from finishup.kernel.projections import ProjectionState
from finishup.kernel.task_facts import (
    effective_obligations,
    observed_run_from_command,
    planned_match,
    requested_command_identity,
    requested_planned_command,
)
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.ledger import CheckObservationsAwaited
from finishup.ports.runtime import RouteAccess, RouteCommand
from finishup.protocol.canonical import JsonValue
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import CheckRequest, StatusClosureReadinessModel

__all__ = [
    "MAX_INSPECTION_ROWS",
    "CheckInspection",
    "check_inspection_json",
    "execute_check_inspection",
    "inspection_alignment",
    "inspection_observed_since",
    "inspection_remaining",
]

# Every list in the result is bounded like the rest of the check wire; the counts beside the
# lists say how many rows exist, so a truncated list never reads as complete.
MAX_INSPECTION_ROWS: Final = 64
_MAX_MISSING: Final = 8
# The observed classes listed: what can have changed the work or that FinishUP cannot prove
# harmless. FinishUP's own calls and host bookkeeping never change the work (``later_material``).
_LISTED_CLASSES: Final = frozenset(
    {
        LaterMaterialClass.EDIT_OR_WRITE,
        LaterMaterialClass.EXPLORATION,
        LaterMaterialClass.NON_COUNTING_WRITE,
        LaterMaterialClass.OTHER,
    }
)
_WRITE_SCOPES: Final = frozenset(
    {"notes", "outside_workspace", "scratch", "workspace", "yoetz_owned"}
)
_OBLIGATION_ORDER: Final = {
    ObligationClosureClass.AGENT_WORK: 0,
    ObligationClosureClass.SETTLED_UNMET: 1,
    ObligationClosureClass.SETTLED_DISCLOSED: 2,
}
_FINDING_ORDER: Final = {
    FindingClosureClass.AGENT_WORK: 0,
    FindingClosureClass.AWAITING_RULING: 1,
    FindingClosureClass.SETTLED_UNMET: 2,
    FindingClosureClass.SETTLED_DISCLOSED: 3,
}
_DECLARED_PATH_KINDS: Final = frozenset({RequestedItemKind.FILE, RequestedItemKind.DIRECTORY})


class Application(StatusApplication, Protocol):
    """The status reads plus nothing else: an inspection needs no write or review port."""


@dataclass(frozen=True, slots=True)
class CheckInspection:
    """One inspection answer, already in its structural wire shape (no privacy projection yet)."""

    request_id: str
    task_id: str
    session_id: str
    writer_id: str
    frontier: Frontier
    remaining: Mapping[str, JsonValue]
    observed_since_check: Mapping[str, JsonValue]
    evidence_alignment: Mapping[str, JsonValue]
    observations_awaited: CheckObservationsAwaited | None = None


def check_inspection_json(result: CheckInspection) -> dict[str, JsonValue]:
    """The inspection branch of check-result 1.4.0 before its privacy projection."""

    body: dict[str, JsonValue] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": result.request_id,
        "ok": True,
        "state": "inspected",
        "task_id": result.task_id,
        "session_id": result.session_id,
        "writer_id": result.writer_id,
        "subject_frontier": dict(result.frontier.as_wire().items()),
        "remaining": dict(result.remaining.items()),
        "observed_since_check": dict(result.observed_since_check.items()),
        "evidence_alignment": dict(result.evidence_alignment.items()),
    }
    if result.observations_awaited is not None:
        body["observations_awaited"] = {
            "state": result.observations_awaited.state,
            "pending_count": str(result.observations_awaited.pending_count),
        }
    return body


def _missing(
    kind: str, owner: Literal["agent", "yoetz"], indexes: Iterable[int] = ()
) -> dict[str, JsonValue]:
    row: dict[str, JsonValue] = {"kind": kind, "owner": owner}
    ordered = sorted(set(indexes))[:MAX_INSPECTION_ROWS]
    if ordered:
        row["item_indexes"] = [str(index) for index in ordered]
    return row


def _obligation_missing(
    projection: ProjectionState,
    records: tuple[LedgerRecord, ...],
    closure: ObligationClosure,
) -> list[JsonValue]:
    """What one agent-work obligation still lacks, and whose move it is."""

    record = projection.obligations.get(closure.obligation_id)
    payload = None if record is None else record.payload
    if payload is None:
        return []
    if closure.basis == "blocker_claimed":
        return [_missing("blocker_unconfirmed", "agent")]
    if closure.basis != "open":
        # ``resolved_deliverable_emptied``: the basis itself names what to restore.
        return []
    rows: list[JsonValue] = []
    attempted = attempted_items_for_obligation(projection, closure.obligation_id)
    unattempted = [
        index
        for index, item in enumerate(payload.requested_items)
        if not value_in_attempted(item.value, attempted)
    ]
    if unattempted:
        rows.append(_missing("requested_item_not_attempted", "agent", unattempted))
    mismatched: list[int] = []
    unobserved: list[int] = []
    for attempt in command_attempts(projection, records, closure.obligation_id):
        index = int(attempt.requested_item_index)
        if attempt.relation == "asserted_observed_mismatch":
            mismatched.append(index)
        elif (
            attempt.relation == "unknown"
            and attempt.asserted_action_ids
            and not attempt.observed_event_ids
        ):
            # The agent asserted the run; no hook observation is linked to it. Whether it ran is
            # outside what FinishUP recorded: an observation gap, not the agent's next move.
            unobserved.append(index)
    if mismatched:
        rows.append(_missing("command_attempt_mismatch", "agent", mismatched))
    if unobserved:
        rows.append(_missing("command_run_not_observed", "yoetz", unobserved))
    if payload.status is ObligationStatus.OPEN and not payload.resolution_evidence_refs:
        rows.append(_missing("resolution_evidence_not_cited", "agent"))
    return rows[:_MAX_MISSING]


def inspection_remaining(
    readiness: StatusClosureReadinessModel,
    projection: ProjectionState,
    records: tuple[LedgerRecord, ...],
    obligations: Iterable[ObligationClosure],
    findings: Iterable[FindingClosure],
) -> dict[str, JsonValue]:
    """Item 1: the closure verdict, and every unresolved obligation and finding with its why."""

    open_obligations = sorted(
        (item for item in obligations if item.closure_class in _OBLIGATION_ORDER),
        key=lambda item: (_OBLIGATION_ORDER[item.closure_class], str(item.obligation_id).encode()),
    )
    open_findings = sorted(
        (item for item in findings if item.closure_class in _FINDING_ORDER),
        key=lambda item: (_FINDING_ORDER[item.closure_class], str(item.finding_id).encode()),
    )
    obligation_rows: list[JsonValue] = []
    for item in open_obligations[:MAX_INSPECTION_ROWS]:
        missing = (
            _obligation_missing(projection, records, item)
            if item.closure_class is ObligationClosureClass.AGENT_WORK
            else []
        )
        obligation_rows.append(
            {
                "obligation_id": str(item.obligation_id),
                "closure_class": item.closure_class.value,
                "closure_basis": item.basis,
                "missing": missing,
            }
        )
    remaining: dict[str, JsonValue] = {
        "readiness": readiness.state or "unknown",
        "agent_actionable": list(readiness.agent_actionable or ()),
        "standing_limitations": list(readiness.standing_limitations or ()),
        "obligations": obligation_rows,
        "obligation_count": str(len(open_obligations)),
        "findings": [
            {
                "finding_id": str(item.finding_id),
                "closure_class": item.closure_class.value,
                "closure_basis": item.basis,
            }
            for item in open_findings[:MAX_INSPECTION_ROWS]
        ],
        "finding_count": str(len(open_findings)),
    }
    predicted = readiness.predicted_receipt
    if predicted is not None:
        remaining["predicted_conclusion"] = predicted.conclusion
    return remaining


def _write_scope(description: str) -> str | None:
    for token in sorted(observed_action_runtime_tokens(description)):
        if token.startswith("write "):
            scope = token.removeprefix("write ")
            if scope in _WRITE_SCOPES:
                return scope
    return None


def inspection_observed_since(
    projection: ProjectionState, records: tuple[LedgerRecord, ...]
) -> dict[str, JsonValue]:
    """Item 2: the hook-observed actions after the last recorded check, newest last."""

    latest = projection.latest_tested_state
    since = 0 if latest is None else latest.subject_frontier.sequence
    exempt = supersession_exempt(projection)
    by_event = observed_actions_by_event(records)
    results_by_action = {
        record.payload.action_id: record.payload
        for record in sorted(projection.results.values(), key=lambda row: row.source_frontier)
        if record.payload is not None
    }
    rows: list[dict[str, JsonValue]] = []
    for record in records:
        if (
            record.ledger.ingestion_sequence <= since
            or record.schema.name != "action_recorded"
            or not is_observation_authored(record)
            or type(record.payload) is not ActionRecordedPayload
        ):
            continue
        material = classify_later_material(
            record, projection, exempt=exempt, actions_by_event=by_event
        )
        if material.material_class not in _LISTED_CLASSES:
            continue
        payload = record.payload
        row: dict[str, JsonValue] = {
            "event_id": str(record.event_id),
            "ledger_sequence": str(record.ledger.ingestion_sequence),
            "action_kind": payload.action_kind.value,
            "material_class": material.material_class.value,
        }
        tool = observed_action_tool(payload.description)
        if tool is not None:
            row["tool_name"] = tool
        scope = _write_scope(payload.description)
        if scope is not None:
            row["write_scope"] = scope
        result = results_by_action.get(payload.action_id)
        if result is not None:
            row["outcome"] = result.outcome.value
            if result.exit_status is not None:
                row["exit_status"] = result.exit_status
        if payload.action_kind is ActionKind.COMMAND:
            commitment = command_identity(payload.command)
            if commitment is not None:
                row["command_commitment"] = commitment
        rows.append(row)
    observed: dict[str, JsonValue] = {
        "actions": cast(list[JsonValue], rows[-MAX_INSPECTION_ROWS:]),
        "action_count": str(len(rows)),
    }
    if latest is not None:
        observed["last_check_frontier"] = str(since)
    return observed


def _declared_items(payload: ObligationPublishedPayload) -> list[tuple[int, str]]:
    declared: list[tuple[int, str]] = []
    for index, item in enumerate(payload.requested_items):
        if item.item_kind is RequestedItemKind.COMMAND or (
            item.item_kind in _DECLARED_PATH_KINDS and item.role is not RequestedItemRole.INPUT
        ):
            declared.append((index, item.item_kind.value))
    return declared[:MAX_INSPECTION_ROWS]


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


def _source_actions(
    projection: ProjectionState,
    records_by_event: Mapping[EventId, LedgerRecord],
    ref: str,
) -> tuple[tuple[ActionRecordedPayload, EventId], ...]:
    """The actions a cited result or evidence item came from, by recorded link."""

    actions: list[tuple[ActionRecordedPayload, EventId]] = []

    def add(action_id: ActionId) -> None:
        record = projection.actions.get(action_id)
        if record is not None and record.payload is not None:
            pair = (record.payload, record.source_event_id)
            if pair not in actions:
                actions.append(pair)

    if ref.startswith("res_"):
        result = projection.results.get(ResultId(ref))
        if result is not None and result.payload is not None:
            add(result.payload.action_id)
        return tuple(actions)
    for result_id in sorted(projection.results, key=lambda value: str(value).encode()):
        result = projection.results[result_id]
        if result.payload is not None and ref in result.payload.evidence_refs:
            add(result.payload.action_id)
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
    return tuple(actions)


def _evidence_outcome(projection: ProjectionState, ref: str) -> str | None:
    if not ref.startswith("res_"):
        return None
    result = projection.results.get(ResultId(ref))
    if result is None or result.payload is None:
        return None
    return result.payload.outcome.value


def inspection_alignment(
    projection: ProjectionState, records: tuple[LedgerRecord, ...]
) -> dict[str, JsonValue]:
    """Item 3: where each obligation's resolution evidence came from, beside what it declared.

    ``evidence_off_declared_items`` is the conservative flag: the obligation declares at least
    one deliverable or command, some cited evidence traces to an action, and no such action names
    a declared item through a recorded link. FinishUP reads no working directory, environment or
    service configuration, so this compares only what the record links.

    A revised plan can carry more obligations than the list bound, so flagged rows come first and
    both counts are taken before the bound: a dropped row is counted and never hides a flag.
    """

    observed_events = observed_event_ids_from_records(records)
    records_by_event = {record.event_id: record for record in records}
    rows: list[dict[str, JsonValue]] = []
    obligations = sorted(effective_obligations(projection), key=lambda value: str(value).encode())
    for obligation in obligations:
        payload = projection.obligations[obligation].payload
        if payload is None or not payload.resolution_evidence_refs:
            continue
        declared = _declared_items(payload)
        sources: list[JsonValue] = []
        attributed = False
        named_any = False
        for ref in tuple(payload.resolution_evidence_refs)[:MAX_INSPECTION_ROWS]:
            actions = _source_actions(projection, records_by_event, str(ref))
            named: set[int] = set()
            commitment: str | None = None
            origin = "unattributed"
            for action, source_event in actions:
                observed = source_event in observed_events
                named |= _named_indexes(payload, declared, action, observed=observed)
                if observed:
                    origin = "observed"
                elif origin == "unattributed":
                    origin = "asserted"
                if commitment is None and action.command is not None:
                    commitment = (
                        command_identity(action.command)
                        if observed
                        else requested_command_identity(action.command)
                    )
            source: dict[str, JsonValue] = {
                "ref": str(ref),
                "origin": origin,
                "named_item_indexes": [str(index) for index in sorted(named)],
            }
            if commitment is not None:
                source["command_commitment"] = commitment
            outcome = _evidence_outcome(projection, str(ref))
            if outcome is not None:
                source["outcome"] = outcome
            sources.append(source)
            attributed = attributed or bool(actions)
            named_any = named_any or bool(named)
        if not declared:
            alignment = "no_declared_items"
        elif named_any:
            alignment = "evidence_names_declared_item"
        elif attributed:
            alignment = "evidence_off_declared_items"
        else:
            alignment = "evidence_unattributed"
        rows.append(
            {
                "obligation_id": str(obligation),
                "alignment": alignment,
                "declared_items": [
                    {"index": str(index), "item_kind": kind} for index, kind in declared
                ],
                "sources": sources,
            }
        )
    flagged = [row for row in rows if row["alignment"] == "evidence_off_declared_items"]
    ranked = flagged + [row for row in rows if row["alignment"] != "evidence_off_declared_items"]
    return {
        "basis": "recorded_links",
        "obligations": cast(list[JsonValue], ranked[:MAX_INSPECTION_ROWS]),
        "obligation_count": str(len(rows)),
        "off_declared_count": str(len(flagged)),
    }


async def execute_check_inspection(
    app: Application,
    request: CheckRequest,
    *,
    route_profile: Literal["policy", "strict"] = "policy",
) -> CheckInspection:
    """Answer one ``mode: inspect`` check from the current record; record nothing.

    Routed as a payload read, exactly like ``status``: no write capability, no frozen case, no
    operation record, no reviewer. ``expected_frontier`` is not compared; the result names the
    frontier it read in ``subject_frontier``.
    """

    if request.mode != "inspect":
        raise TypeError("check_inspection_mode_invalid")
    runtime = await app.runtime.route(
        RouteCommand(
            request.session_id,
            request.writer_id,
            RouteAccess.PAYLOAD_READ,
            frozenset({RuntimeCapability.STRUCTURAL_READ, RuntimeCapability.PAYLOAD_READ}),
        )
    )
    try:
        if runtime.session_id != request.session_id or runtime.writer_id != request.writer_id:
            raise PublicOperationError(
                PublicErrorCode.SESSION_CONFLICT, "The writer route is inconsistent.", False
            )
        frontier, readiness = await current_closure_readiness(
            app, runtime, request.request_id, route_profile=route_profile
        )
        loaded = await load_closure_basis(runtime, frontier)
        projection, records = loaded.projection, loaded.records
        return CheckInspection(
            request.request_id,
            runtime.task_id,
            runtime.session_id,
            cast(str, runtime.writer_id),
            frontier,
            inspection_remaining(
                readiness,
                projection,
                records,
                loaded.basis.obligations,
                loaded.basis.findings,
            ),
            inspection_observed_since(projection, records),
            inspection_alignment(projection, records),
        )
    finally:
        await app.runtime.release(runtime)
