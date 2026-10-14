"""Which task facts bear on one finding (tb4n2 R4 / P1-2, issue #1018, ADR-042).

Task facts (``kernel.task_facts``) describe the task's own work: a planned verification not run, a
requested output Git would not deliver, an edit after the last verification run. Closure readiness
and the Stop gate keep every one of them task-wide: they are work the agent owes whatever finding
is open. A finding's resolution reasons, however, carry the codes of the whole check as
``coverage:<code>``, so an unrelated fact used to disqualify an unrelated finding from
``respond self_verified`` (tb4n2 interleaved S: ``edited_after_last_verification`` blocked two
review findings about the decoder's benchmark result).

The scope rule is structural and replay-derived:

* an obligation-scoped fact (its marker names an obligation) bears on a finding only when the
  finding is about that obligation: an obligation subject ref, a claim subject ref naming it (a
  completion claim naming none covers every effective obligation), or an action event subject ref
  naming it;
* the task-wide ``edited_after_last_verification`` bears only on a finding about verification or
  evidence (the kinds in ``VERIFICATION_FINDING_KINDS``);
* ``command_attempt_mismatch`` (tb4n5, #1049) is keyed per obligation and requested command item
  (``kernel.command_attempts``): it bears on a finding about a mismatched obligation, about an
  action that asserted the mismatched item or about a run or result linked into that relation,
  and on nothing else (tb4n5 react S: a mismatch on a command obligation refused ``self_verified``
  on an ``action_without_result`` finding about an edit action that named no obligation). A
  mismatch FinishUP cannot locate at the current prefix bears (fail closed);
* every other code, including every non-task-fact code, bears as before.

Only ``scoped_resolution_reasons`` changes what a caller sees; nothing here changes a fact, a
finding's resolution, closure readiness or the Stop gate.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final, cast

from finishup.domain.events import ClaimKind, LedgerRecord
from finishup.domain.findings import FindingKind
from finishup.domain.values import (
    ActionId,
    ClaimId,
    EventId,
    EvidenceId,
    FindingId,
    ObligationId,
    ResultId,
)
from finishup.kernel.command_attempts import command_attempts
from finishup.kernel.projections import ProjectionRecord, ProjectionState
from finishup.kernel.task_facts import (
    EDITED_AFTER_LAST_VERIFICATION_GAP,
    TASK_FACT_GAPS,
    command_identity_key_generation,
    effective_obligations,
    task_fact_signals,
)

__all__ = [
    "COMMAND_ATTEMPT_MISMATCH_GAP",
    "VERIFICATION_FINDING_KINDS",
    "CommandMismatch",
    "command_mismatch_bears_on_finding",
    "command_mismatches",
    "command_mismatches_for_finding",
    "finding_obligation_scope",
    "scoped_resolution_reasons",
    "task_fact_bears_on_finding",
]

# Findings about whether the work was verified, or whether evidence still describes it: the only
# findings a task-wide "edited after the last verification run" fact says anything about.
VERIFICATION_FINDING_KINDS: Final = frozenset(
    {
        FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
        FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM,
        FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE,
        FindingKind.FAILED_WORK_OMITTED,
        FindingKind.WEAK_OR_STALE_RESPONSE,
        FindingKind.LEDGER_STALE_OR_INCOMPLETE,
    }
)
_TASK_WIDE_SCOPED: Final = frozenset({EDITED_AFTER_LAST_VERIFICATION_GAP})
_CHECK_TIME_FACTS: Final = frozenset(
    code
    for code in TASK_FACT_GAPS
    if code.startswith("requested_output_") or code.startswith("declared_output_")
)
_COVERAGE_PREFIX: Final = "coverage:"
COMMAND_ATTEMPT_MISMATCH_GAP: Final = "command_attempt_mismatch"
_MISMATCH_REASON: Final = _COVERAGE_PREFIX + COMMAND_ATTEMPT_MISMATCH_GAP
# Subject prefixes this scope reads; a subject of any other kind keeps the mismatch (fail closed).
_SCOPED_SUBJECT_PREFIXES: Final = ("obl_", "clm_", "evt_", "act_", "res_", "evd_")


@dataclass(frozen=True, slots=True)
class CommandMismatch:
    """One requested command item whose linked observed runs all ran another command.

    ``item_index`` is the item's index in the obligation's ``requested_items``; the action and
    event ids are the asserted actions and the linked observed run events
    (``kernel.command_attempts``). Every value is a ledger id or an index, never command text.
    """

    obligation_id: ObligationId
    item_index: int
    asserted_action_ids: tuple[str, ...]
    observed_event_ids: tuple[str, ...]


# One entry: the last (projection, prefix) asked and its rows. Status scopes every current finding
# against the same immutable projection and record tuple, so the rows are derived once per read;
# holding the objects keeps their identities from being reused while the entry stands.
_MISMATCH_MEMO: list[
    tuple[ProjectionState, tuple[LedgerRecord, ...], int, tuple[CommandMismatch, ...]]
] = []


def command_mismatches(
    state: ProjectionState, records: tuple[LedgerRecord, ...]
) -> tuple[CommandMismatch, ...]:
    """Every effective obligation's mismatched requested command items, in obligation order."""

    generation = command_identity_key_generation()
    if _MISMATCH_MEMO:
        memo_state, memo_records, memo_generation, memo_rows = _MISMATCH_MEMO[0]
        if memo_state is state and memo_records is records and memo_generation == generation:
            return memo_rows
    rows = _command_mismatch_rows(state, records)
    _MISMATCH_MEMO[:] = [(state, records, generation, rows)]
    return rows


def _command_mismatch_rows(
    state: ProjectionState, records: tuple[LedgerRecord, ...]
) -> tuple[CommandMismatch, ...]:
    rows: list[CommandMismatch] = []
    for obligation in sorted(effective_obligations(state), key=lambda value: str(value).encode()):
        record = state.obligations.get(obligation)
        if record is None or record.payload is None:
            continue
        for attempt in command_attempts(state, records, obligation):
            if attempt.relation == "asserted_observed_mismatch":
                rows.append(
                    CommandMismatch(
                        obligation,
                        int(attempt.requested_item_index),
                        tuple(attempt.asserted_action_ids),
                        tuple(attempt.observed_event_ids),
                    )
                )
    return tuple(rows)


def _readable[T](record: ProjectionRecord[T] | None) -> T | None:
    """The payload of a projection row that exists and is readable, else ``None``."""

    if record is None or record.payload is None or record.redacted:
        return None
    return record.payload


def _mismatch_related(
    state: ProjectionState, finding_id: FindingId, row: CommandMismatch
) -> bool | None:
    """Whether one mismatch row is about the finding; ``None`` when a subject cannot be placed.

    Related: a subject is the mismatched obligation, a claim naming it (a completion claim naming
    none covers every effective obligation), an action that asserted the item or names the
    obligation, the linked observed run (its action or result, by event or id), or a result or
    evidence the obligation cites for its resolution (or the action behind such a result).

    Fail closed (tb4n5 check D1/D2): a subject that is missing, redacted or unreadable, an event
    this projection cannot place, or a subject of another kind is unknown, so the mismatch stays
    (``None``). Only a subject every link of which was read and found unrelated is ``False``.
    """

    finding = _readable(state.findings.get(finding_id))
    if finding is None:
        return None
    target = row.obligation_id
    obligation = _readable(state.obligations.get(target))
    cited: frozenset[str] = (
        frozenset()
        if obligation is None
        else frozenset(map(str, obligation.resolution_evidence_refs))
    )
    observed_events = frozenset(row.observed_event_ids)
    linked_actions = set(row.asserted_action_ids)
    for key, result in state.results.items():
        payload = _readable(result)
        if payload is not None and str(key) in cited:
            linked_actions.add(str(payload.action_id))
    by_event: dict[str, tuple[str, str]] = {}
    for kind, table in (
        ("act", state.actions),
        ("res", state.results),
        ("evd", state.evidence),
        ("obl", state.obligations),
        ("clm", state.claims),
    ):
        for key, item in table.items():
            by_event.setdefault(str(item.source_event_id), (kind, str(key)))

    def action_related(action_key: str) -> bool | None:
        action_record = state.actions.get(ActionId(action_key))
        payload = _readable(action_record)
        if action_record is None or payload is None:
            return None
        return (
            action_key in linked_actions
            or str(action_record.source_event_id) in observed_events
            or target in payload.obligation_refs
        )

    def related(kind: str, key: str) -> bool | None:
        if kind == "obl":
            if _readable(state.obligations.get(ObligationId(key))) is None:
                return None
            return key == str(target)
        if kind == "clm":
            claim = _readable(state.claims.get(ClaimId(key)))
            if claim is None:
                return None
            if claim.obligation_refs:
                return target in claim.obligation_refs
            return claim.claim_kind is ClaimKind.COMPLETION and target in set(
                effective_obligations(state)
            )
        if kind == "act":
            return action_related(key)
        if kind == "res":
            result = _readable(state.results.get(ResultId(key)))
            if result is None:
                return None
            if key in cited:
                return True
            return action_related(str(result.action_id))
        if kind == "evd":
            if _readable(state.evidence.get(EvidenceId(key))) is None:
                return None
            if key in cited:
                return True
            for result in state.results.values():
                payload = _readable(result)
                if payload is not None and key in map(str, payload.evidence_refs):
                    verdict = action_related(str(payload.action_id))
                    if verdict is None or verdict:
                        return verdict
            return False
        return None

    for ref in finding.subject_refs:
        text = str(ref)
        if not text.startswith(_SCOPED_SUBJECT_PREFIXES):
            return None
        if text.startswith("evt_"):
            if text in observed_events:
                return True
            placed = by_event.get(text)
            if placed is None:
                # An event this projection cannot place: keep the mismatch (fail closed).
                return None
            kind, key = placed
        else:
            kind, key = text[:3], text
        verdict = related(kind, key)
        if verdict is None or verdict:
            return verdict
    return False


def command_mismatches_for_finding(
    state: ProjectionState, finding_id: FindingId, mismatches: Iterable[CommandMismatch]
) -> tuple[CommandMismatch, ...]:
    """The mismatch rows about this finding; every row when one cannot be placed (fail closed)."""

    rows = tuple(mismatches)
    related: list[CommandMismatch] = []
    for row in rows:
        verdict = _mismatch_related(state, finding_id, row)
        if verdict is None:
            return rows
        if verdict:
            related.append(row)
    return tuple(related)


def command_mismatch_bears_on_finding(
    state: ProjectionState, finding_id: FindingId, mismatches: Iterable[CommandMismatch]
) -> bool:
    """Whether a listed ``command_attempt_mismatch`` says anything about *finding_id*.

    A mismatch the current prefix cannot locate (no mismatched row) bears: the check that listed
    it saw one, and nothing here can say which obligation it was about.
    """

    rows = tuple(mismatches)
    if not rows:
        return True
    return bool(command_mismatches_for_finding(state, finding_id, rows))


def finding_obligation_scope(
    state: ProjectionState, finding_id: FindingId
) -> frozenset[ObligationId]:
    """The obligations one finding is about; empty when it names none (or is unknown)."""

    record = state.findings.get(finding_id)
    if record is None or record.payload is None:
        return frozenset()
    scope: set[ObligationId] = set()
    actions_by_event = {
        action.source_event_id: action.payload
        for action in state.actions.values()
        if action.payload is not None
    }
    for ref in record.payload.subject_refs:
        text = str(ref)
        if text.startswith("obl_"):
            scope.add(ObligationId(text))
        elif text.startswith("clm_"):
            item = state.claims.get(ClaimId(text))
            claim = None if item is None else item.payload
            if claim is None:
                continue
            if claim.obligation_refs:
                scope.update(claim.obligation_refs)
            elif claim.claim_kind is ClaimKind.COMPLETION:
                scope.update(effective_obligations(state))
        elif text.startswith("evt_"):
            action = actions_by_event.get(EventId(text))
            if action is not None:
                scope.update(action.obligation_refs)
    return frozenset(scope)


def task_fact_bears_on_finding(
    code: str,
    *,
    state: ProjectionState,
    finding_id: FindingId,
    markers: Iterable[tuple[str, ObligationId | None]] | None,
) -> bool:
    """Whether the task-fact *code* says anything about *finding_id*.

    ``markers`` are ``task_fact_signals(state, records).markers`` for the same prefix, or ``None``
    when unknown: obligation-scoped codes then count as bearing (fail closed). A code that is not a
    task fact always bears (unchanged behaviour).
    """

    if code not in TASK_FACT_GAPS:
        return True
    record = state.findings.get(finding_id)
    if record is None or record.payload is None:
        return True
    if code in _TASK_WIDE_SCOPED:
        return record.payload.kind in VERIFICATION_FINDING_KINDS
    if code in _CHECK_TIME_FACTS or markers is None:
        # Requested- and declared-output facts come from the check-time workspace read, never
        # from ``task_fact_signals``: their obligation scope is not replayable here, so they bear
        # (fail closed).
        return True
    named = {obligation for marker, obligation in markers if marker == code}
    if None in named:
        # A task-wide fact (an install, a write outside the workspace, verification only as
        # root): a standing disclosure, kept wherever it appears.
        return True
    if _scope_unreadable(state, finding_id):
        # tb4n5 check D1: a claim or obligation subject (or the action an event subject records)
        # that is missing or redacted cannot show which obligations the finding is about.
        return True
    return bool(named & finding_obligation_scope(state, finding_id))


def _scope_unreadable(state: ProjectionState, finding_id: FindingId) -> bool:
    """Whether a subject ``finding_obligation_scope`` reads is missing or unreadable."""

    finding = _readable(state.findings.get(finding_id))
    if finding is None:
        return True
    placed = _placed_events(state)
    for ref in finding.subject_refs:
        text = str(ref)
        if text.startswith("obl_"):
            if _readable(state.obligations.get(ObligationId(text))) is None:
                return True
        elif text.startswith("clm_"):
            if _readable(state.claims.get(ClaimId(text))) is None:
                return True
        elif text.startswith("evt_"):
            # tb4n5 check D6: an event the projection cannot place (no row records it) is as
            # unknown as an unreadable one; only a placed, readable event can show the scope.
            row = placed.get(text)
            if row is None or _readable(row) is None:
                return True
    return False


def _placed_events(state: ProjectionState) -> dict[str, ProjectionRecord[object]]:
    """Every projection row by the event that recorded it (the newest row of a key wins)."""

    placed: dict[str, ProjectionRecord[object]] = {}
    tables: tuple[Iterable[object], ...] = (
        state.obligations.values(),
        state.decisions.values(),
        state.assignments.values(),
        state.actions.values(),
        state.results.values(),
        state.evidence.values(),
        state.claims.values(),
        state.findings.values(),
        state.responses.values(),
        state.coordination_contexts.values(),
        state.coordination_dispositions.values(),
        state.coordination_declarations.values(),
    )
    for table in tables:
        for row in table:
            typed = cast(ProjectionRecord[object], row)
            placed.setdefault(str(typed.source_event_id), typed)
    for plan in state.plans.values():
        placed.setdefault(str(plan.source_event_id), cast(ProjectionRecord[object], plan))
    return placed


def scoped_resolution_reasons(
    reasons: tuple[str, ...],
    *,
    state: ProjectionState,
    finding_id: FindingId,
    records: tuple[LedgerRecord, ...] | None,
) -> tuple[str, ...]:
    """*reasons* without the ``coverage:<task fact>`` reasons that do not bear on the finding.

    ``records`` is the exact prefix ``state`` replays (``None`` when unavailable: only the
    task-wide edited-after-verification scoping applies then). Order is kept. When every reason
    would be dropped the original reasons are returned unchanged.
    """

    task_fact_reasons = [
        reason
        for reason in reasons
        if reason.startswith(_COVERAGE_PREFIX) and reason[len(_COVERAGE_PREFIX) :] in TASK_FACT_GAPS
    ]
    mismatch_listed = _MISMATCH_REASON in reasons
    if not task_fact_reasons and not mismatch_listed:
        return reasons
    dropped: set[str] = set()
    if task_fact_reasons:
        markers = None if records is None else task_fact_signals(state, records).markers
        dropped.update(
            reason
            for reason in task_fact_reasons
            if not task_fact_bears_on_finding(
                reason[len(_COVERAGE_PREFIX) :],
                state=state,
                finding_id=finding_id,
                markers=markers,
            )
        )
    if (
        mismatch_listed
        and records is not None
        and not command_mismatch_bears_on_finding(
            state, finding_id, command_mismatches(state, records)
        )
    ):
        dropped.add(_MISMATCH_REASON)
    scoped = tuple(reason for reason in reasons if reason not in dropped)
    # When an unrelated task fact is the only thing left between the finding and its resolution,
    # keep it: the agent clears it by doing that work (re-running its verification), and saying
    # "nothing blocks" would be false.
    return scoped if scoped else reasons
