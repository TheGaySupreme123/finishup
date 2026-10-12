"""Evidence-bounded command reconciliation; no shell parsing, execution, or live reads."""

from __future__ import annotations

import posixpath
from collections.abc import Iterable
from typing import TYPE_CHECKING

from yoetz.domain.events import ActionKind, LedgerRecord, is_observation_authored
from yoetz.domain.values import ActionId, EventId, ObligationId, ResultId
from yoetz.kernel.projections import ProjectionState
from yoetz.protocol.models import StatusCommandAttemptModel

if TYPE_CHECKING:
    from yoetz.kernel.task_facts import ObservedCommandRun


def same_requested_path(requested: str, other: str) -> bool:
    """Whether two spellings name the same requested file or directory (ADR-045).

    ``attempted_items`` and a requested value used to match only byte for byte, so
    ``out/build.log`` never matched ``/app/out/build.log`` and ``./solve.sage`` never matched
    ``solve.sage`` (retro S: ``requested_item_never_attempted`` on files it had written). Both
    are normalised lexically (``.`` and ``..`` folded, no filesystem access). Two absolute paths
    match only when equal; otherwise the relative one matches when its components are the tail of
    the other's. The tail rule trades a rare false match (two files of one name in different
    directories) for the common true one (the agent's relative spelling of an absolute value).
    """

    if type(requested) is not str or type(other) is not str or not requested or not other:
        return False
    first = posixpath.normpath(requested.strip())
    second = posixpath.normpath(other.strip())
    if first == second:
        return True
    first_absolute, second_absolute = first.startswith("/"), second.startswith("/")
    if first_absolute and second_absolute:
        return False
    first_parts = [part for part in first.split("/") if part not in {"", "."}]
    second_parts = [part for part in second.split("/") if part not in {"", "."}]
    if not first_parts or not second_parts or ".." in first_parts or ".." in second_parts:
        return False
    shorter, longer = sorted((first_parts, second_parts), key=len)
    return longer[len(longer) - len(shorter) :] == shorter


def value_in_attempted(value: str, attempted: Iterable[str]) -> bool:
    """Whether *value* is among *attempted*, exactly or as the same file path (ADR-045)."""

    items = tuple(attempted)
    return value in items or any(same_requested_path(value, item) for item in items)


def attempted_items_for_obligation(
    state: ProjectionState,
    obligation_id: ObligationId,
    *,
    action_kind: ActionKind | None = None,
) -> frozenset[str]:
    """Return action assertions attributable to one obligation.

    An action with no ``obligation_refs`` is an explicitly global assertion and may
    cover every obligation.  Once an action names obligations, its attempted items
    belong only to those exact ids.  Keeping this rule in one helper makes the
    status projection and deterministic requested-item policy agree (#967).
    ``action_kind`` keeps only actions of that kind (the requested-output facts read edits).
    """

    return frozenset(
        item
        for record in state.actions.values()
        if record.payload is not None
        and (action_kind is None or record.payload.action_kind is action_kind)
        and (not record.payload.obligation_refs or obligation_id in record.payload.obligation_refs)
        for item in record.payload.attempted_items
    )


def command_attempts(
    state: ProjectionState, records: tuple[LedgerRecord, ...], obligation_id: ObligationId
) -> tuple[StatusCommandAttemptModel, ...]:
    """Compare only explicitly linked observations; unrelated commands prove nothing.

    A cooperative action may name an observed action event as a causal parent. An obligation's
    resolution result may name an observed action. Both are explicit relevance assertions, not
    temporal correlation. Service-stamped authorship supplies the independent observation fact.
    Missing, ambiguous, or redacted command bytes stay unknown. A keyed observed command (the
    hook's installation-keyed commitments, never text) is compared with the planned command by
    the shared matcher of ``task_facts`` (ADR-045): the same command, the same command up to
    wrappers, or a run that began with the planned arguments or carried its program and flags.
    """

    from yoetz.kernel.task_facts import (  # lazy: task_facts imports this module
        observed_run_from_command,
        planned_match,
        requested_planned_command,
    )

    obligation = state.obligations[obligation_id].payload
    if obligation is None:
        return ()
    by_event = {
        row.event_id: row for row in records if row.ledger.ingestion_sequence <= state.frontier
    }
    output: list[StatusCommandAttemptModel] = []
    for index, requested in enumerate(obligation.requested_items):
        if requested.item_kind.value != "command":
            continue
        assertions = [
            record
            for record in state.actions.values()
            if record.payload is not None
            and requested.value in record.payload.attempted_items
            and (
                not record.payload.obligation_refs
                or obligation_id in record.payload.obligation_refs
            )
        ]
        linked: set[EventId] = set()
        for assertion in assertions:
            event = by_event.get(assertion.source_event_id)
            if event is not None:
                linked.update(event.causal_parents)
                if is_observation_authored(event):
                    linked.add(event.event_id)
        for ref in obligation.resolution_evidence_refs:
            if not ref.startswith("res_"):
                continue
            result = state.results.get(ResultId(ref))
            if result is not None and result.payload is not None:
                action = state.actions.get(result.payload.action_id)
                if action is not None:
                    linked.add(action.source_event_id)
        observed = [
            row
            for key in sorted(linked)
            if (row := by_event.get(key)) is not None
            and is_observation_authored(row)
            and row.schema.name == "action_recorded"
        ]
        commands: set[str | None] = set()
        keyed_runs: list[ObservedCommandRun] = []
        for row in observed:
            key = row.projection_locator.logical_key
            action = state.actions.get(ActionId(key)) if key is not None else None
            if action is None or action.payload is None or action.source_event_id != row.event_id:
                commands.add(None)
            elif action.payload.action_kind.value == "command":
                commands.add(action.payload.command)
                run = observed_run_from_command(action.payload.command)
                if run is not None:
                    keyed_runs.append(run)
            else:
                commands.add(None)
        unavailable = not commands or any(
            value is None or value.startswith("omitted:") for value in commands
        )
        relation = "unknown"
        if not unavailable and len(commands) == 1:
            relation = (
                "matching_observed_attempt"
                if requested.value in commands
                else "asserted_observed_mismatch"
            )
        elif commands and len(keyed_runs) == len(commands) and None not in commands:
            # ADR-045: every linked observed action carries a keyed command identity, so the
            # planned command is compared with them by the shared matcher (exact, up to wrappers,
            # or by leading arguments or flags) instead of byte for byte against nothing.
            planned = requested_planned_command(requested.value)
            if planned is not None:
                relation = (
                    "matching_observed_attempt"
                    if any(planned_match(run, planned) is not None for run in keyed_runs)
                    else "asserted_observed_mismatch"
                )
        # Without an assertion this is evidence discovery, not an asserted/observed disagreement.
        if not assertions and relation == "asserted_observed_mismatch":
            relation = "unknown"
        if len(assertions) > 64 or len(observed) > 64:
            relation = "unknown"
        output.append(
            StatusCommandAttemptModel.model_validate(
                {
                    "requested_item_index": str(index),
                    "relation": relation,
                    "asserted_action_ids": sorted(
                        {
                            str(row.payload.action_id)
                            for row in assertions
                            if row.payload is not None
                        }
                    )[:64],
                    "observed_event_ids": sorted({str(row.event_id) for row in observed})[:64],
                }
            )
        )
    return tuple(output)


def closure_command_gaps(
    state: ProjectionState, records: tuple[LedgerRecord, ...]
) -> tuple[tuple[ObligationId, str], ...]:
    """Completion-time limits for asserted commands, without asserting they never ran."""
    from yoetz.kernel.claims import effective_claim_items

    selected = {
        ref
        for _, claim in effective_claim_items(state)
        if claim.payload is not None and claim.payload.claim_kind.value == "completion"
        for ref in claim.payload.obligation_refs
    }
    selected.update(
        key
        for key, row in state.obligations.items()
        if row.payload is not None and row.payload.status.value == "resolved"
    )
    from yoetz.kernel.plan_scope import current_plan_scope

    scope = current_plan_scope(state.plans, state.coverage_gaps)
    selected.intersection_update(scope.effective_obligation_refs or ())
    gaps: set[tuple[ObligationId, str]] = set()
    for key in sorted(selected):
        if key not in state.obligations:
            continue
        for attempt in command_attempts(state, records, key):
            if attempt.relation == "unknown":
                gaps.add((key, "command_attempt_uncorroborated"))
            elif attempt.relation == "asserted_observed_mismatch":
                gaps.add((key, "command_attempt_mismatch"))
    return tuple(sorted(gaps))
