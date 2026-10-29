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
from finishup.domain.values import ActionId, EventId, ObligationId, ResultId
from finishup.domain.verification_coverage import (
    CRITERION_SENTENCE_BREAK,
    MAX_COVERAGE_CRITERIA,
    MAX_CRITERION_WITNESSES,
    VERIFICATION_COVERAGE_FLAGS,
    CoverageFlag,
    CriterionSource,
    VerificationCoverage,
    VerificationCriterion,
    VerificationWitness,
    criterion_quote_in_text,
    criterion_quote_pattern,
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
from finishup.kernel.verification_freshness import (
    VerificationFreshness,
    retained_verification_runs,
    verification_freshness,
    verification_tracked_runs,
)

__all__ = [
    "build_verification_coverage",
    "criterion_obligations",
    "verification_coverage_to_json",
]

# Case-tolerant, with present-tense and plural forms: "Outputs", "returns" and "labels" state
# conditions as plainly as their base forms (#1170 pilot wording). Past tenses and participles
# ("written", "produced", "required", "requirements.txt") usually describe what already
# happened, so alone they propose no criterion; a stated requirement still matches through its
# modal or quantifier. A plural noun ("The labels were produced by annotators.") can still
# propose a descriptive sentence: a visible, bounded false gap rather than a hidden criterion.
_REQUIREMENT_WORDS: Final = (
    r"must|shall|requires?|requiring|outputs?|outputting|returns?|returning|produc(?:e|es|ing)|"
    r"deliver(?:s|ing)?|writ(?:e|es|ing)|sav(?:e|es|ing)|labels?|label(?:l)?ing"
)
_QUANTIFIER_WORDS: Final = r"every|each|at least|at most|no more than|no less than"
_CONDITION: Final = re.compile(
    rf"\b(?:{_REQUIREMENT_WORDS}|{_QUANTIFIER_WORDS})\b|[≤≥]", re.IGNORECASE
)
MAX_CRITERION_QUOTE_CHARACTERS: Final = 240
_SENTENCE: Final = CRITERION_SENTENCE_BREAK
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


def _candidate_sentences(text: str, *, explicit: bool) -> tuple[str, ...]:
    # Preserve verbatim substrings. A long sentence is not silently clipped into a different
    # condition; it is counted as omitted, and only its bounded manifest quote can represent it.
    return tuple(
        quote
        for sentence in _SENTENCE.split(text)
        if (quote := sentence.strip()) and (explicit or _CONDITION.search(quote))
    )


def _criterion_key(text: str) -> str:
    """One criterion however it is cased, spaced or ended (a restated task sentence)."""

    return " ".join(text.casefold().split()).rstrip(".!?;:")


def _occurs(quote: str, text: str) -> bool:
    """The admission rule's whole-word occurrence; a generic legacy quote keeps plain matching
    so its own row, and any failures it declares, stay visible (it can map no criterion)."""

    pattern = criterion_quote_pattern(quote)
    return quote in text if pattern is None else pattern.search(text) is not None


def _outside_quotes(candidate: str, quotes: Collection[str]) -> str:
    remainder = candidate
    for quote in sorted(quotes, key=len, reverse=True):
        pattern = criterion_quote_pattern(quote)
        if pattern is not None:
            remainder = pattern.sub("\0", remainder)
    # A simple quantified context qualifies the witnessed clause, rather than stating a
    # second condition. Retain quantified predicates and numerical bounds outside it.
    remainder = re.sub(
        r"\b(?:for|on|over|across)\s+(?:every|each)\s+[\w-]+(?=\s*(?:[,;:.!?]|\x00|$))",
        " ",
        remainder,
        flags=re.IGNORECASE,
    )
    return re.sub(r"\b(?:every|each)\s*(?=\x00)", " ", remainder, flags=re.IGNORECASE)


def criterion_obligations(projection: ProjectionState, quote: str) -> tuple[ObligationId, ...]:
    """Effective obligations whose acceptance criteria state *quote*, sorted (#975 draft receipt).

    The index's own matching only: the quote occurs in the criteria text (the admission rule,
    ``_occurs``), or one of its candidate sentences is the same criterion however cased, spaced
    or ended (``_criterion_key``, the rule that merges a restated sentence into the task's). No
    other text similarity links an obligation to a criterion.
    """

    key = _criterion_key(quote)
    found: list[ObligationId] = []
    for obligation in effective_obligations(projection):
        payload = projection.obligations[obligation].payload
        text = None if payload is None else payload.acceptance_criteria
        if not text:
            continue
        if _occurs(quote, text) or any(
            _criterion_key(sentence) == key
            for sentence in _candidate_sentences(text, explicit=True)
        ):
            found.append(obligation)
    return tuple(sorted(found, key=str.encode))


def _strength(run: _Run) -> tuple[int, int, int, int]:
    return (
        2 if run.witness.freshness == "current" else int(not run.witness.stale),
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
    freshness: tuple[VerificationFreshness, ...] | None = None,
    tracked_runs: tuple[ResultId, ...] | None = None,
) -> VerificationCoverage:
    """Project declarations at this frontier; no finding, gate, or closure consequence.

    ``task_statement`` lets frozen semantic cases supply their separately admitted task text.
    Otherwise the authenticated prefix, then plan-carried text, supplies the statement.
    Frozen callers pass both ``freshness`` and ``tracked_runs`` from the case, including empty
    tuples. Without that pair, only a live authenticated prefix can derive per-run judgments;
    old frozen cases and unjudged runs keep a labeled legacy latest-edit candidate.
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
    if records and freshness is None and tracked_runs is None:
        freshness = verification_freshness(projection, records)
        tracked_runs = verification_tracked_runs(projection, records)
    states = {row.run_ref: row.state for row in freshness or ()}
    judged = frozenset(tracked_runs or ()) if freshness is not None else frozenset[ResultId]()
    if not records and judged:
        # Before #1194, frozen inventories included older duplicates the engine never judged.
        # Recover only retention here, using frozen inputs; never rerun the freshness predicates.
        first_positions: dict[ActionId, int] = {}
        frozen_runs: list[tuple[ResultId, int, EventId]] = []
        for ref, row in sorted(
            projection.results.items(), key=lambda item: item[1].source_frontier
        ):
            result = row.payload
            if result is None:
                continue
            position = first_positions.setdefault(result.action_id, row.source_frontier)
            action = projection.actions.get(result.action_id)
            if ref in judged and action is not None and action.payload is not None:
                frozen_runs.append((ref, position, action.source_event_id))
        judged = retained_verification_runs(projection, frozen_runs)
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
            _occurs(manifest.criterion_quote, task_statement)
            if task_statement is not None
            else any(_occurs(manifest.criterion_quote, text) for text, _ in sources)
        )
        if not valid_quote:
            continue
        action_row = projection.actions.get(payload.action_id)
        action = None if action_row is None else action_row.payload
        freshness_state = (
            states.get(payload.result_id, "current")
            if payload.result_id in judged and action is not None
            else "legacy"
        )
        witness = VerificationWitness(
            payload.result_id,
            payload.action_id,
            manifest.data_source.value,
            manifest.cases,
            manifest.failing,
            manifest.tuned_on_these_cases,
            manifest.worst,
            freshness_state == "stale"
            or freshness_state == "legacy"
            and row.source_frontier < latest_edit,
            freshness_state,
            # Display-only (#1219): never in a run identity, a flag or the witness ranking.
            checks=manifest.checks,
            expected_from=(
                None if manifest.expected_from is None else manifest.expected_from.value
            ),
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

    # The task statement is listed first, so identical text keeps the task source; the review
    # packet's span resolves the same way.
    criteria: dict[str, CriterionSource] = {
        quote: next(source for text, source in sources if _occurs(quote, text))
        for quote in runs_by_quote
    }
    # One candidate per criterion: a restated, recased or re-ended obligation sentence is the
    # task sentence it repeats, and keeps the task source (the task statement is listed first).
    candidates: dict[str, CriterionSource] = {}
    seen_keys: set[str] = set()
    too_long: set[str] = set()
    for text, source in sources:
        for sentence in _candidate_sentences(text, explicit=source == "obligation"):
            key = _criterion_key(sentence)
            if len(sentence) > MAX_CRITERION_QUOTE_CHARACTERS:
                too_long.add(key)
            elif key not in seen_keys:
                seen_keys.add(key)
                candidates[sentence] = source
    mapped: dict[str, list[str]] = {}
    for known in runs_by_quote:
        # A cited clause maps the one task candidate it identifies, and any obligation sentence
        # that restates it, so a longer sentence around the exact quote is not a false second
        # gap. A generic or cross-sentence quote, or one in several task candidates, identifies
        # none and cannot erase another criterion.
        equal = [quote for quote in candidates if quote.split() == known.split()]
        within = [quote for quote in candidates if criterion_quote_in_text(known, quote)]
        in_task = [quote for quote in within if candidates[quote] == "task_statement"]
        targets = equal or (
            [*in_task, *(quote for quote in within if candidates[quote] == "obligation")]
            if len(in_task) == 1
            else within
            if not in_task and len(within) == 1
            else []
        )
        if len(in_task) == 1:
            targets = list(
                dict.fromkeys(
                    [*targets, *(quote for quote in within if candidates[quote] == "obligation")]
                )
            )
        for quote in targets:
            mapped.setdefault(quote, []).append(known)
    # A quote retires its sentence only when nothing outside the quoted text states another
    # condition: in "The labels must be saved and the ratio must be at most 1.06." a ratio
    # witness leaves the sentence visible as a gap beside the witness row.
    covered = {
        quote
        for quote, quotes in mapped.items()
        if not _CONDITION.search(_outside_quotes(quote, quotes))
    }
    for quote, source in candidates.items():
        if quote not in covered:
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
        current = [run for run in present if run.witness.freshness == "current"]
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
        if present and all(run.witness.stale for run in present):
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
    # Retained failures lead. The user's task criteria then precede obligation acceptance
    # prose, so agent-written sentences can never push a task gap past the display bound.
    # Within a source, gaps precede rows without candidate gaps. This is a display ordering,
    # never an invitation to increase the number of tests.
    rows.sort(
        key=lambda row: (
            "failing_cases" not in row.flags,
            row.source == "obligation",
            "no_test" not in row.flags,
            not row.flags,
            row.criterion_quote.encode(),
        )
    )
    # Sentences longer than a manifest quote cannot be shown; they are counted, never dropped.
    return VerificationCoverage(
        tuple(rows[:MAX_COVERAGE_CRITERIA]),
        max(0, len(rows) - MAX_COVERAGE_CRITERIA) + len(too_long),
    )
