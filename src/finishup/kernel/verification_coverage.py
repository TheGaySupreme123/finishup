"""Replay-pure, advisory test coverage from bounded agent declarations (#1170).

Counts never earn a score. A current independent witness is displayed ahead of volume, and
each check's latest failing declaration stays visible until that same check is rerun. Text
matching finds candidate criteria only; it cannot decide whether a test measures its quote.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from typing import Final

from finishup.domain.events import ActionKind, LedgerRecord, ResultOutcome, ResultRecordedPayload
from finishup.domain.task_statement import current_task_statement
from finishup.domain.values import ActionId
from finishup.domain.verification_coverage import (
    MAX_COVERAGE_CRITERIA,
    MAX_CRITERION_WITNESSES,
    VERIFICATION_COVERAGE_FLAGS,
    CoverageFlag,
    CriterionSource,
    VerificationCoverage,
    VerificationCriterion,
    VerificationWitness,
    verification_coverage_to_json,
)
from finishup.kernel.observed_failures import (
    command_identity,
    observed_edit_counts,
    observed_event_ids_from_records,
    observed_shell_write_counts,
    observed_write_stales_verification,
)
from finishup.kernel.projections import ProjectionRecord, ProjectionState
from finishup.kernel.task_facts import (
    effective_obligations,
    non_counting_edits_exempt,
    stale_exempt_write_tokens,
    verification_unchanged_actions,
    workspace_verification_edits,
)

__all__ = ["build_verification_coverage", "verification_coverage_to_json"]

_CONDITION: Final = re.compile(
    r"\b(?:must|shall|every|each|at least|at most|no more than|no less than|"
    r"required|output|return|produce|deliver|write|save|label)\b|[≤≥]",
    re.IGNORECASE,
)
_SENTENCE: Final = re.compile(r"(?<=[.!?])\s+|[\n;]+")
_SOURCE_RANK: Final = {
    "independent": 4,
    "held_out": 4,
    "stated_environment": 3,
    "task_public": 2,
    "own_generated": 1,
    "unknown": 0,
}


@dataclass(frozen=True, slots=True)
class _Run:
    row: ProjectionRecord[ResultRecordedPayload]
    witness: VerificationWitness
    identity: tuple[str, str, bool | None, int]
    state: object | None
    test_file: str | None


def _material_edits(projection: ProjectionState, unchanged: frozenset[ActionId]) -> tuple[int, ...]:
    exempt = non_counting_edits_exempt(projection)
    stale_exempt = stale_exempt_write_tokens(projection)
    edits: list[int] = []
    # Plans, resolutions, receipts and polling never enter this collection. Reuse the shared
    # write classes so scratch and documentation edits keep the same staleness meaning.
    for row in projection.actions.values():
        action = row.payload
        if action is None:
            continue
        counts = (
            action.action_kind is ActionKind.EDIT
            and observed_edit_counts(action.description, exempt)
        ) or (
            action.action_kind is ActionKind.COMMAND
            and action.action_id not in unchanged
            and observed_shell_write_counts(action.description, exempt)
        )
        if counts and observed_write_stales_verification(action.description, stale_exempt):
            edits.append(row.source_frontier)
    return tuple(sorted(edits))


def _candidate_quotes(text: str, *, explicit: bool) -> tuple[str, ...]:
    # Preserve verbatim substrings. A long sentence is not silently clipped into a different
    # condition; only its bounded manifest quote can represent it.
    return tuple(
        quote
        for sentence in _SENTENCE.split(text)
        if (quote := sentence.strip())
        and len(quote) <= 240
        and (explicit or _CONDITION.search(quote))
    )


def _strength(run: _Run) -> tuple[int, int, int, int]:
    return (
        not run.witness.stale,
        run.witness.tuned_on_these_cases is not True,
        _SOURCE_RANK[run.witness.data_source],
        run.row.source_frontier,
    )


def build_verification_coverage(
    projection: ProjectionState,
    records: Sequence[LedgerRecord] = (),
    *,
    task_statement: str | None = None,
    unchanged_action_ids: Collection[ActionId] | None = None,
    workspace_verification_edit_frontier: int = 0,
) -> VerificationCoverage:
    """Project declarations at this frontier; no finding, gate, or closure consequence.

    ``task_statement`` lets frozen semantic cases supply their separately admitted task text.
    Otherwise the authenticated prefix, then plan-carried text, supplies the statement.
    """

    if task_statement is None:
        statement = current_task_statement(records)
        task_statement = None if statement is None else statement.text
    if task_statement is None:
        plans = sorted(projection.plans.values(), key=lambda row: row.source_frontier, reverse=True)
        task_statement = next(
            (
                row.payload.task_statement
                for row in plans
                if row.payload is not None and row.payload.task_statement is not None
            ),
            None,
        )
    sources: list[tuple[str, CriterionSource]] = []
    if task_statement:
        sources.append((task_statement, "task_statement"))
    for obligation in effective_obligations(projection):
        payload = projection.obligations[obligation].payload
        if payload is not None and payload.acceptance_criteria:
            sources.append((payload.acceptance_criteria, "obligation"))

    unchanged = (
        verification_unchanged_actions(projection, records)
        if unchanged_action_ids is None
        else frozenset(unchanged_action_ids)
    )
    edits = tuple(
        sorted(
            set(_material_edits(projection, unchanged))
            | {
                position
                for position, _ in workspace_verification_edits(
                    projection, observed_event_ids_from_records(records), records
                )
            }
            | (
                {workspace_verification_edit_frontier}
                if workspace_verification_edit_frontier
                else set()
            )
        )
    )
    latest_edit = edits[-1] if edits else 0
    runs_by_quote: dict[str, list[_Run]] = {}
    for row in sorted(projection.results.values(), key=lambda row: row.source_frontier):
        payload = row.payload
        if payload is None or payload.verification is None:
            continue
        manifest = payload.verification
        # Match admission's current-task rule when that text is available. An old effective
        # obligation may remain a candidate, but cannot preserve a removed task's witness.
        # Legacy projections without task text can still use readable obligation criteria.
        valid_quote = (
            manifest.criterion_quote in task_statement
            if task_statement is not None
            else any(manifest.criterion_quote in text for text, _ in sources)
        )
        if not valid_quote:
            continue
        action_row = projection.actions.get(payload.action_id)
        action = None if action_row is None else action_row.payload
        witness = VerificationWitness(
            payload.result_id,
            payload.action_id,
            manifest.data_source.value,
            manifest.cases,
            manifest.failing,
            manifest.tuned_on_these_cases,
            manifest.worst,
            row.source_frontier < latest_edit,
        )
        # A different command, provenance, tuning status, or case count cannot erase a failed
        # condition. Absent a readable command, this run cannot supersede any earlier run.
        command = (
            str(payload.action_id) if action is None or action.command is None else action.command
        )
        identity = (command, witness.data_source, witness.tuned_on_these_cases, witness.cases)
        if command.startswith("omitted:") and command_identity(command) is None:
            # An opaque placeholder is not an identity: unrelated observed commands often
            # share it. They must not retire each other's failures.
            command = str(payload.action_id)
            identity = (command, witness.data_source, witness.tuned_on_these_cases, witness.cases)
        subject = payload.subject_state or (None if action is None else action.subject_state)
        state: object | None = (
            (subject.tree_digest, subject.diff_digest)
            if subject is not None
            and (subject.tree_digest is not None or subject.diff_digest is not None)
            else None
        )
        if state is None and not projection.coverage_gaps:
            # A candidate repeat on the same *recorded* work, not a filesystem claim. A
            # known coverage gap suppresses this fallback because edits may be missing.
            epoch = bisect_right(edits, row.source_frontier)
            state = ("recorded_material_edit_epoch", epoch)
        runs_by_quote.setdefault(manifest.criterion_quote, []).append(
            _Run(row, witness, identity, state, manifest.test_file)
        )

    criteria: dict[str, CriterionSource] = {
        quote: next(source for text, source in sources if quote in text) for quote in runs_by_quote
    }
    for text, source in sources:
        for quote in _candidate_quotes(text, explicit=source == "obligation"):
            matching = [known for known in runs_by_quote if known in quote or quote in known]
            if matching:
                # A cited clause maps its candidate sentence. Do not add a false no-test row
                # merely because the task includes a longer sentence around the exact quote.
                for known in matching:
                    criteria[known] = source
            else:
                criteria.setdefault(quote, source)

    rows: list[VerificationCriterion] = []
    for quote, source in criteria.items():
        runs = runs_by_quote.get(quote, [])
        latest_by_check: dict[tuple[str, str, bool | None, int], _Run] = {}
        repeat_seen: set[tuple[object, ...]] = set()
        repeated = 0
        for run in runs:
            prior = latest_by_check.get(run.identity)
            if (
                prior is None
                or not prior.witness.failing
                or run.witness.failing
                or (
                    run.row.payload is not None and run.row.payload.outcome is ResultOutcome.SUCCESS
                )
            ):
                latest_by_check[run.identity] = run
            # Explicit state commitments win; otherwise this is only a candidate repeat on
            # the same recorded material-edit generation, never proof of filesystem identity.
            if run.state is not None:
                key = (run.identity, run.state, run.witness.failing, run.witness.worst)
                repeated += key in repeat_seen
                repeat_seen.add(key)
        latest = list(latest_by_check.values())
        failing = [run for run in latest if run.witness.failing > 0]
        present = [run for run in latest if run.witness.cases > 0]
        current = [run for run in present if not run.witness.stale]
        scope = current or present
        redundant_keys: set[tuple[object, ...]] = set()
        redundant = 0
        for run in latest:
            if run.state is not None and run.test_file is not None:
                key = (
                    run.test_file,
                    run.state,
                    run.witness.data_source,
                    run.witness.cases,
                    run.witness.failing,
                    run.witness.worst,
                    run.witness.tuned_on_these_cases,
                )
                redundant += key in redundant_keys
                redundant_keys.add(key)
        flags: set[CoverageFlag] = set()
        if not present:
            flags.add("no_test")
        if failing:
            flags.add("failing_cases")
        if scope and all(
            run.witness.data_source == "own_generated" or run.witness.tuned_on_these_cases is True
            for run in scope
        ):
            flags.add("own_or_tuned_only")
        if scope and all(run.witness.data_source == "task_public" for run in scope):
            flags.add("public_only")
        if present and not current:
            flags.add("stale")
        if repeated:
            flags.add("repeated_run")
        if redundant:
            flags.add("redundant_tests")
        selected: list[_Run] = []
        if latest:
            selected.append(max(present or latest, key=_strength))
        for run in sorted(failing, key=lambda item: item.row.source_frontier, reverse=True):
            if run not in selected and len(selected) < MAX_CRITERION_WITNESSES:
                selected.append(run)
        rows.append(
            VerificationCriterion(
                quote,
                source,
                tuple(flag for flag in VERIFICATION_COVERAGE_FLAGS if flag in flags),
                tuple(run.witness for run in selected),
                len(failing),
                repeated,
                redundant,
                max(0, len(latest) - len(selected)),
            )
        )
    # Gaps and retained failures stay visible before rows without candidate gaps. This is a
    # display ordering, never an invitation to increase the number of tests.
    rows.sort(
        key=lambda row: (
            "failing_cases" not in row.flags,
            "no_test" not in row.flags,
            not row.flags,
            row.criterion_quote.encode(),
        )
    )
    return VerificationCoverage(
        tuple(rows[:MAX_COVERAGE_CRITERIA]), max(0, len(rows) - MAX_COVERAGE_CRITERIA)
    )
