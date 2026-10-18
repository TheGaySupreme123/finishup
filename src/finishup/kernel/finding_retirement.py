"""Retire an observed failed-command finding on a later passing run (#1104, owner decision D2).

The observation coordinator records a ``failed_work_omitted`` finding seconds after a hook reports
a failed shell call (rule ``failed_command_unresolved``). The advice rule itself stops reporting
the failure once a later run of the same command passes (#909), but the recorded finding had no
lifecycle of its own, so it stayed open and receipt-blocking after the repair. This module gives
it one, derived at replay from events the ledger already holds:

* An **observed failed-command finding** is an observation-authored ``finding_recorded`` that is
  deterministic, ``policy_id == "work-integrity"``, of kind ``failed_work_omitted`` and names no
  claim (``clm_``) in ``subject_refs``. The work-integrity pack's own finding always names its
  claim, so the two never mix, and only the coordinator authors the first.
* Its **failed run** is the one service-stamped hook-observed ``result_recorded`` with outcome
  ``failure`` or ``partial`` whose source event the finding names, else the one such result of a
  call the finding names (by its action event or any of its result events). The second form is
  how a Codex failure is found: the hook recorded the call with an ``unknown`` outcome, the
  finding names that call's events, and the session stream's outcome correction (#1001) is the
  failed result linked to the same action. When neither is unique the finding has no failed run:
  a rerun cannot retire it and only an answer settles it.
* A **later pass** retires it: a hook-observed result recorded after the failed run, with outcome
  ``success`` (a host-stated exit 0 or ``success: true``, or a stream correction stating one), of a
  *different* call whose action was recorded after the failed call's first hook-observed result
  (when FinishUP first knew that call had finished: a pass that began before it, in parallel or
  with a lagging Codex correction, is no repair of it), and whose observed ``command`` action is
  one of:

  - **the same command**: it has the failed run's keyed identity or certifies it as one of its
    exact segments (``observed_failures.success_certified_identities``: a segment of a passing
    ``single`` or ``and_chain`` command that ran exactly as listed, so a leading assignment or
    ``env``/``nohup``/``exec``/``time`` wrapper certifies nothing). This is the shared
    supersession rule (``observed_failures.classify_observed_runs``) with one narrowing: the
    passing result must belong to another call, so a conflicting second outcome for the same call
    never retires it.
  - **a planned verification** (owner decisions 2026-10-18, recorded on #1104): a run that is
    a verifier (its recorded runner class is ``test``, ``build``, ``lint`` or ``typecheck``,
    ``observed_failures.observed_action_is_verifier``) and passed a command an obligation
    requests that was effective when the run passed, matched by the recorded ADR-033 rule
    (``task_facts.planned_verification_passed``: the keyed whole-command commitment, or the
    planned command as a certified segment of a passing ``single`` or ``and_chain`` run, under
    the same bare-segment rule as above; a planned command that masks its own outcome never
    counts). "When the run passed" is the passing call's first hook-observed result (its pass
    point, the call floor below), and the plan is the one effective just before it
    (``task_facts.planned_verification_commands(effective_at=...)``): only plan events recorded
    before the pass point, and only an obligation first published before it, count, so a plan
    or obligation published or introduced by a revision after the pass retires nothing, and a
    later revision that supersedes the obligation does not undo the retirement. The
    obligation's status and waiver are read as the ledger records them now, as before: a later
    ``acknowledged_not_done`` or waiver un-retires what only that match retired (the agent's own
    statement that the obligation is not being done; a reverse state the replay re-derives).
    It retires every earlier observed failed command, related or not: a passing planned
    verification also clears an unrelated earlier failure (a failed install), a trade-off the
    owner accepted. A planned ``true`` or ``ls`` is no verifier and retires nothing. Without the
    installation key no run is a planned verification.

  An ``unknown`` outcome never retires anything, an edit never does, and a run of another,
  unplanned command never does. When one run is both, it is recorded as the same command.

The fact is stored on the finding record (``retired_by_event_id``, ``retired_frontier``, and
``retired_by_planned_verification`` for the second kind) and every surface reads it through
``finding_resolution.finding_is_resolved``; the closure basis is ``retired_by_passing_run`` or
``retired_by_planned_verification``. Redacting the passing run, the failed run, its action or the
finding drops the fact (unreadable proof is no proof). Nothing is deleted: the finding stays in
history.

The reducer calls the incremental entry points (``on_finding_recorded``, ``on_observed_result``,
``on_plan_changed``) in ledger order. An observed failure costs one pass over the results (to name
its call's events) plus a set test per unlinked candidate, and rescans the ledger only for a
candidate that names that call; a success costs O(linked candidates); a plan or obligation
event re-derives every linked candidate; ``recompute_all`` re-derives the same facts from a
whole projection after a redaction. All follow one definition (a pure function of the current
projection and the installation key), so a full replay and an incremental fold agree.
"""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Callable, Mapping, Sequence, Set
from dataclasses import replace
from typing import Final

from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    ResultOutcome,
    ResultRecordedPayload,
)
from finishup.domain.findings import Finding, FindingKind, FindingOrigin
from finishup.domain.values import ActionId, EventId, FindingId, ResultId
from finishup.kernel.observed_failures import (
    command_identity,
    observed_action_is_verifier,
    success_certified_identities,
)
from finishup.kernel.projections import FindingProjectionRecord, ProjectionRecord
from finishup.kernel.task_facts import PlannedCommand, planned_verification_passed

__all__ = [
    "failed_run_of",
    "is_observed_failed_command_finding",
    "is_observed_failed_command_shape",
    "no_planned_verifications",
    "on_finding_recorded",
    "on_observed_result",
    "on_plan_changed",
    "recompute_all",
    "retirement_witness",
]

type _Results = Mapping[ResultId, ProjectionRecord[ResultRecordedPayload]]
type _Actions = Mapping[ActionId, ProjectionRecord[ActionRecordedPayload]]
# The planned verifications effective just before a ledger sequence (a passing call's pass point),
# computed only when a retirement needs them.
type PlannedVerifications = Callable[[int], Sequence[PlannedCommand]]
# A retirement: the passing run's source event, its frontier, and whether it retired the finding
# as a planned verification (``False``: the same command passed).
type Witness = tuple[EventId, int, bool]


def no_planned_verifications(point: int) -> Sequence[PlannedCommand]:
    """The planned verifications of a projection with no plan (and the default)."""

    del point
    return ()


_FAILED_OUTCOMES: Final = frozenset({ResultOutcome.FAILURE, ResultOutcome.PARTIAL})
_POLICY_ID: Final = "work-integrity"


def is_observed_failed_command_shape(finding: Finding) -> bool:
    """The payload half of the definition: a claimless deterministic failed-work finding."""

    return (
        finding.kind is FindingKind.FAILED_WORK_OMITTED
        and finding.origin is FindingOrigin.DETERMINISTIC
        and finding.policy_id == _POLICY_ID
        and not any(str(ref).startswith("clm_") for ref in finding.subject_refs)
    )


def is_observed_failed_command_finding(record: FindingProjectionRecord | None) -> bool:
    """A readable observed failed-command finding (authorship stamped at replay)."""

    return (
        record is not None
        and record.payload is not None
        and record.observed_failed_command
        and is_observed_failed_command_shape(record.payload)
    )


def _named_failures(
    finding: Finding, results: _Results, actions: _Actions, observed: Set[EventId]
) -> tuple[list[tuple[int, ResultId]], list[tuple[int, ResultId]]]:
    """The hook-observed failed results *finding* names directly, and through their call.

    A call is named by its action event or by any of its result events: the coordinator names
    the events the failed envelope materialized, and on Codex those are the call's action and
    its ``unknown`` hook result, while the failure itself is the session stream's correction
    linked to the same action.
    """

    refs = frozenset(str(ref) for ref in finding.subject_refs)
    named_actions = {
        key
        for key, action in actions.items()
        if action.payload is not None
        and action.source_event_id in observed
        and str(action.source_event_id) in refs
    }
    named_actions.update(
        record.payload.action_id
        for record in results.values()
        if record.payload is not None
        and record.source_event_id in observed
        and str(record.source_event_id) in refs
    )
    direct: list[tuple[int, ResultId]] = []
    by_action: list[tuple[int, ResultId]] = []
    for key, record in results.items():
        payload = record.payload
        if (
            payload is None
            or record.source_event_id not in observed
            or payload.outcome not in _FAILED_OUTCOMES
        ):
            continue
        if str(record.source_event_id) in refs:
            direct.append((record.source_frontier, key))
        elif payload.action_id in named_actions:
            by_action.append((record.source_frontier, key))
    return direct, by_action


def _unique_through(
    direct: list[tuple[int, ResultId]], by_action: list[tuple[int, ResultId]], through: int
) -> ResultId | None:
    named = [key for frontier, key in direct if frontier <= through]
    if named:
        return named[0] if len(named) == 1 else None
    linked = [key for frontier, key in by_action if frontier <= through]
    return linked[0] if len(linked) == 1 else None


def failed_run_of(
    finding: Finding,
    results: _Results,
    actions: _Actions,
    observed: Set[EventId],
    *,
    through: int,
) -> ResultId | None:
    """The one hook-observed failed result *finding* names, recorded no later than ``through``."""

    direct, by_action = _named_failures(finding, results, actions, observed)
    return _unique_through(direct, by_action, through)


def _command_action_record(
    result: ProjectionRecord[ResultRecordedPayload] | None,
    actions: _Actions,
    observed: Set[EventId],
) -> ProjectionRecord[ActionRecordedPayload] | None:
    if result is None or result.payload is None or result.source_event_id not in observed:
        return None
    action = actions.get(result.payload.action_id)
    if (
        action is None
        or action.payload is None
        or action.source_event_id not in observed
        or action.payload.action_kind is not ActionKind.COMMAND
    ):
        return None
    return action


def _command_action(
    result: ProjectionRecord[ResultRecordedPayload] | None,
    actions: _Actions,
    observed: Set[EventId],
) -> ActionRecordedPayload | None:
    action = _command_action_record(result, actions, observed)
    return None if action is None else action.payload


def _call_floors(results: _Results, observed: Set[EventId]) -> dict[ActionId, int]:
    """Per call, the frontier of its earliest readable hook-observed result.

    That is when FinishUP first learned the call had finished: its own failure on Claude Code or
    Cursor, its outcome-less hook result on Codex (whose exit lands later, as a stream
    correction). A pass whose call was recorded no later than this point of the failed call
    started before the failure was known, so it is never a repair of it, however late its own
    outcome (a lagging Codex correction, a parallel call) reaches the ledger.
    """

    floors: dict[ActionId, int] = {}
    for record in results.values():
        payload = record.payload
        if payload is None or record.source_event_id not in observed:
            continue
        known = floors.get(payload.action_id)
        if known is None or record.source_frontier < known:
            floors[payload.action_id] = record.source_frontier
    return floors


def _failed_record(
    failed: ResultId, results: _Results
) -> ProjectionRecord[ResultRecordedPayload] | None:
    record = results.get(failed)
    if record is None or record.payload is None or record.payload.outcome not in _FAILED_OUTCOMES:
        return None
    return record


def _failed_identity(
    failed: ProjectionRecord[ResultRecordedPayload], actions: _Actions, observed: Set[EventId]
) -> str | None:
    """The failed run's keyed identity; ``None`` when no same-command pass can name it.

    A failed run without one (``omitted:structural``, an unkeyed or identity-less call) can still
    be retired by a passing planned verification, which never compares it with anything.
    """

    action = _command_action(failed, actions, observed)
    return None if action is None else command_identity(action.command)


def _memoized(planned: PlannedVerifications) -> PlannedVerifications:
    """Compute the planned verifications at most once per point, and only if some candidate asks."""

    computed: dict[int, Sequence[PlannedCommand]] = {}

    def read(point: int) -> Sequence[PlannedCommand]:
        known = computed.get(point)
        if known is None:
            known = computed[point] = planned(point)
        return known

    return read


class _Passes:
    """The hook-observed passing command runs of one projection, in ledger order.

    Built once per derivation. A row's identity, certified segments and planned-verification match
    are read lazily and kept, so re-deriving many candidates parses each run at most once, and a
    candidate scans only the runs recorded after its failed run, up to the first that retires it.
    """

    __slots__ = (
        "_floors",
        "_frontiers",
        "_identities",
        "_observed",
        "_planned",
        "_planned_rows",
        "_results",
        "_rows",
    )

    def __init__(
        self,
        results: _Results,
        actions: _Actions,
        observed: Set[EventId],
        planned: PlannedVerifications,
    ) -> None:
        rows: list[
            tuple[ProjectionRecord[ResultRecordedPayload], ProjectionRecord[ActionRecordedPayload]]
        ] = []
        for record in results.values():
            payload = record.payload
            if payload is None or payload.outcome is not ResultOutcome.SUCCESS:
                continue
            action = _command_action_record(record, actions, observed)
            if action is not None:
                rows.append((record, action))
        rows.sort(key=lambda row: row[0].source_frontier)
        self._rows = rows
        self._frontiers = [row[0].source_frontier for row in rows]
        self._planned = _memoized(planned)
        self._identities: dict[int, tuple[str | None, frozenset[str]]] = {}
        self._planned_rows: dict[int, bool] = {}
        self._results = results
        self._observed = observed
        self._floors: dict[ActionId, int] | None = None

    def _floor(self, call: ActionId, failed_frontier: int) -> int:
        if self._floors is None:
            self._floors = _call_floors(self._results, self._observed)
        return self._floors.get(call, failed_frontier)

    def _same_command(self, index: int, identity: str) -> bool:
        known = self._identities.get(index)
        if known is None:
            action = self._rows[index][1].payload
            assert action is not None
            command = action.command
            known = (command_identity(command), success_certified_identities(command))
            self._identities[index] = known
        return known[0] == identity or identity in known[1]

    def _planned_verification(self, index: int) -> bool:
        known = self._planned_rows.get(index)
        if known is None:
            record, action_record = self._rows[index]
            action = action_record.payload
            payload = record.payload
            assert action is not None and payload is not None
            known = observed_action_is_verifier(action) and planned_verification_passed(
                action.command,
                self._planned(self._floor(payload.action_id, record.source_frontier)),
            )
            self._planned_rows[index] = known
        return known

    def witness(
        self, failed: ProjectionRecord[ResultRecordedPayload], identity: str | None
    ) -> Witness | None:
        failed_payload = failed.payload
        assert failed_payload is not None
        floor: int | None = None
        for index in range(bisect_right(self._frontiers, failed.source_frontier), len(self._rows)):
            record, action = self._rows[index]
            payload = record.payload
            assert payload is not None
            if payload.action_id == failed_payload.action_id:
                continue
            if floor is None:
                floor = self._floor(failed_payload.action_id, failed.source_frontier)
            if action.source_frontier <= floor:
                # The passing call was recorded before the failed call finished.
                continue
            if identity is not None and self._same_command(index, identity):
                return (record.source_event_id, record.source_frontier, False)
            if self._planned_verification(index):
                return (record.source_event_id, record.source_frontier, True)
        return None


def _retires(
    candidate: ProjectionRecord[ResultRecordedPayload],
    action: ProjectionRecord[ActionRecordedPayload],
    failed: ProjectionRecord[ResultRecordedPayload],
    identity: str | None,
    planned_pass: Callable[[], bool],
    floor: Callable[[ActionId, int], int],
) -> bool | None:
    """Whether the passing *candidate* retires *failed*: ``None`` when it does not, else whether it
    does so as a planned verification (``False``: the same command passed)."""

    payload = candidate.payload
    failed_payload = failed.payload
    command = action.payload
    if (
        payload is None
        or failed_payload is None
        or command is None
        or payload.outcome is not ResultOutcome.SUCCESS
        or candidate.source_frontier <= failed.source_frontier
        or payload.action_id == failed_payload.action_id
    ):
        return None
    if identity is not None and (
        command_identity(command.command) == identity
        or identity in success_certified_identities(command.command)
    ):
        kind = False
    elif planned_pass():
        kind = True
    else:
        return None
    # Checked last, so the call floors are read only for a pass that would otherwise retire.
    if action.source_frontier <= floor(failed_payload.action_id, failed.source_frontier):
        return None
    return kind


def retirement_witness(
    failed: ResultId,
    results: _Results,
    actions: _Actions,
    observed: Set[EventId],
    planned: PlannedVerifications = no_planned_verifications,
) -> Witness | None:
    """The source event, frontier and kind of the earliest later pass that retires ``failed``."""

    record = _failed_record(failed, results)
    if record is None:
        return None
    return _Passes(results, actions, observed, planned).witness(
        record, _failed_identity(record, actions, observed)
    )


def _with_failed_run(
    record: FindingProjectionRecord,
    failed: ResultId | None,
    results: _Results,
    actions: _Actions,
    observed: Set[EventId],
    passes: _Passes,
) -> FindingProjectionRecord:
    failed_record = None if failed is None else _failed_record(failed, results)
    witness = (
        None
        if failed_record is None
        else passes.witness(failed_record, _failed_identity(failed_record, actions, observed))
    )
    return replace(
        record,
        failed_run_result_id=failed,
        retired_by_event_id=None if witness is None else witness[0],
        retired_frontier=None if witness is None else witness[1],
        retired_by_planned_verification=witness is not None and witness[2],
    )


def on_finding_recorded(
    findings: dict[FindingId, FindingProjectionRecord],
    key: FindingId,
    results: _Results,
    actions: _Actions,
    observed: Set[EventId],
    observation_findings: Set[EventId],
    planned: PlannedVerifications = no_planned_verifications,
) -> None:
    """Stamp a just-folded finding record and derive its failed run and retirement."""

    record = findings[key]
    payload = record.payload
    if (
        payload is None
        or record.source_event_id not in observation_findings
        or not is_observed_failed_command_shape(payload)
    ):
        return
    stamped = replace(record, observed_failed_command=True)
    failed = failed_run_of(payload, results, actions, observed, through=record.source_frontier)
    passes = _Passes(results, actions, observed, planned)
    findings[key] = _with_failed_run(stamped, failed, results, actions, observed, passes)


def _call_event_ids(action_key: ActionId, results: _Results, actions: _Actions) -> frozenset[str]:
    """The source events of one call: its action event and every result event linked to it."""

    events = {
        str(record.source_event_id)
        for record in results.values()
        if record.payload is not None and record.payload.action_id == action_key
    }
    action = actions.get(action_key)
    if action is not None:
        events.add(str(action.source_event_id))
    return frozenset(events)


def on_observed_result(
    findings: dict[FindingId, FindingProjectionRecord],
    result_key: ResultId,
    results: _Results,
    actions: _Actions,
    observed: Set[EventId],
    planned: PlannedVerifications = no_planned_verifications,
) -> None:
    """Fold one just-recorded hook-observed result into every open candidate.

    A failure may be the failed run of a finding recorded before it (the Codex outcome
    correction can land after the finding names the call); a success may retire a finding whose
    failed run it reruns, or every open one whose failed run it follows when it passed a planned
    verification. Anything else changes nothing.
    """

    new = results.get(result_key)
    if new is None or new.payload is None or new.source_event_id not in observed:
        return
    outcome = new.payload.outcome
    if outcome in _FAILED_OUTCOMES:
        # The new failure can change ``failed_run_of`` only for a finding that names it or its
        # call (``_named_failures``). Collect the call's events once, so each unlinked finding
        # costs a set test instead of a scan of the whole ledger (a lifecycle-anchored finding
        # stays unlinked for good).
        call_events = _call_event_ids(new.payload.action_id, results, actions)
        passes: _Passes | None = None
        for key, record in tuple(findings.items()):
            payload = record.payload
            if (
                payload is None
                or not record.observed_failed_command
                or record.failed_run_result_id is not None
                or call_events.isdisjoint(str(ref) for ref in payload.subject_refs)
            ):
                continue
            failed = failed_run_of(payload, results, actions, observed, through=new.source_frontier)
            if failed is not None:
                if passes is None:
                    passes = _Passes(results, actions, observed, planned)
                findings[key] = _with_failed_run(record, failed, results, actions, observed, passes)
        return
    if outcome is not ResultOutcome.SUCCESS:
        return
    action = _command_action_record(new, actions, observed)
    if action is None or action.payload is None:
        return
    passing = action.payload
    passing_call = new.payload.action_id
    command = passing.command
    planned_once = _memoized(planned)
    verdict: list[bool] = []
    floors: list[dict[ActionId, int]] = []

    def planned_pass() -> bool:
        # The new run's planned-verification match against the plan effective at its pass point,
        # computed once for every candidate.
        if not verdict:
            verdict.append(
                observed_action_is_verifier(passing)
                and planned_verification_passed(
                    command, planned_once(floor(passing_call, new.source_frontier))
                )
            )
        return verdict[0]

    def floor(call: ActionId, failed_frontier: int) -> int:
        # One scan of the results, only once some candidate would otherwise retire.
        if not floors:
            floors.append(_call_floors(results, observed))
        return floors[0].get(call, failed_frontier)

    for key, record in tuple(findings.items()):
        failed = record.failed_run_result_id
        if record.payload is None or failed is None or record.retired_by_event_id is not None:
            continue
        failed_record = _failed_record(failed, results)
        if failed_record is None:
            continue
        kind = _retires(
            new,
            action,
            failed_record,
            _failed_identity(failed_record, actions, observed),
            planned_pass,
            floor,
        )
        if kind is not None:
            findings[key] = replace(
                record,
                retired_by_event_id=new.source_event_id,
                retired_frontier=new.source_frontier,
                retired_by_planned_verification=kind,
            )


def on_plan_changed(
    findings: dict[FindingId, FindingProjectionRecord],
    results: _Results,
    actions: _Actions,
    observed: Set[EventId],
    current: PlannedVerifications,
) -> None:
    """Re-derive every linked candidate's retirement after a plan or obligation event.

    A pass is judged against the plan effective at its pass point, so a plan or obligation
    published after it never makes it count. The obligation's status and waiver are read as the
    ledger records them now, so a later ``acknowledged_not_done`` republication or waiver (or an
    unreadable plan event) stops a pass that matched only that obligation from retiring what
    only it retired, and a republication that reopens the obligation lets it retire again.
    Nothing is computed while no candidate has a failed run.
    """

    if not any(
        record.observed_failed_command and record.failed_run_result_id is not None
        for record in findings.values()
    ):
        return
    passes = _Passes(results, actions, observed, current)
    for key, record in tuple(findings.items()):
        if not record.observed_failed_command or record.failed_run_result_id is None:
            continue
        updated = _with_failed_run(
            record, record.failed_run_result_id, results, actions, observed, passes
        )
        if updated != record:
            findings[key] = updated


def _derived_failed_run(
    record: FindingProjectionRecord, results: _Results, actions: _Actions, observed: Set[EventId]
) -> ResultId | None:
    """The failed run the incremental fold would have fixed, from the whole projection.

    The fold fixes it when the finding is recorded, else at the first later observed failure
    after which exactly one named failure exists; only a named failure can change the answer.
    """

    payload = record.payload
    assert payload is not None
    direct, by_action = _named_failures(payload, results, actions, observed)
    moments = sorted(
        {record.source_frontier}
        | {
            frontier
            for frontier, _key in (*direct, *by_action)
            if frontier > record.source_frontier
        }
    )
    for through in moments:
        failed = _unique_through(direct, by_action, through)
        if failed is not None:
            return failed
    return None


def recompute_all(
    findings: dict[FindingId, FindingProjectionRecord],
    results: _Results,
    actions: _Actions,
    observed: Set[EventId],
    planned: PlannedVerifications = no_planned_verifications,
) -> None:
    """Re-derive every candidate's failed run and retirement after a redaction.

    An unreadable finding, failed run, action, passing run or plan clears what depended on it,
    exactly as a full replay of the readable records would derive it.
    """

    passes = _Passes(results, actions, observed, planned)
    for key, record in tuple(findings.items()):
        if not record.observed_failed_command:
            continue
        if record.payload is None:
            if record.failed_run_result_id is not None or record.retired_by_event_id is not None:
                findings[key] = replace(
                    record,
                    failed_run_result_id=None,
                    retired_by_event_id=None,
                    retired_frontier=None,
                    retired_by_planned_verification=False,
                )
            continue
        failed = _derived_failed_run(record, results, actions, observed)
        updated = _with_failed_run(record, failed, results, actions, observed, passes)
        if updated != record:
            findings[key] = updated
