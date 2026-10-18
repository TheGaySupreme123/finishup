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
  *different* call, whose observed ``command`` action has the failed run's keyed identity or
  certifies it as one of its exact segments (``observed_failures.success_certified_identities``:
  a passing ``single`` or ``and_chain`` command). The rule is the shared supersession rule
  (``observed_failures.classify_observed_runs``) with one narrowing: the passing result must belong
  to another call, so a conflicting second outcome for the same call never retires it. An
  ``unknown`` outcome never retires anything, an edit never does, and a run of another command
  never does.

The fact is stored on the finding record (``retired_by_event_id``, ``retired_frontier``) and every
surface reads it through ``finding_resolution.finding_is_resolved``; the closure basis is
``retired_by_passing_run``. Redacting the passing run, the failed run, its action or the finding
drops the fact (unreadable proof is no proof). Nothing is deleted: the finding stays in history.

The reducer calls the incremental entry points (``on_finding_recorded``, ``on_observed_result``)
in ledger order, which costs O(open candidates) per observed result; ``recompute_all`` re-derives
the same facts from a whole projection after a redaction. Both follow one definition, so a full
replay and an incremental fold agree.
"""

from __future__ import annotations

from collections.abc import Mapping, Set
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
from finishup.kernel.observed_failures import command_identity, success_certified_identities
from finishup.kernel.projections import FindingProjectionRecord, ProjectionRecord

__all__ = [
    "failed_run_of",
    "is_observed_failed_command_finding",
    "is_observed_failed_command_shape",
    "on_finding_recorded",
    "on_observed_result",
    "recompute_all",
    "retirement_witness",
]

type _Results = Mapping[ResultId, ProjectionRecord[ResultRecordedPayload]]
type _Actions = Mapping[ActionId, ProjectionRecord[ActionRecordedPayload]]

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


def _command_action(
    result: ProjectionRecord[ResultRecordedPayload] | None,
    actions: _Actions,
    observed: Set[EventId],
) -> ActionRecordedPayload | None:
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
    return action.payload


def _failed_identity(
    failed: ResultId, results: _Results, actions: _Actions, observed: Set[EventId]
) -> str | None:
    record = results.get(failed)
    if record is None or record.payload is None or record.payload.outcome not in _FAILED_OUTCOMES:
        return None
    action = _command_action(record, actions, observed)
    return None if action is None else command_identity(action.command)


def _certifies(
    candidate: ProjectionRecord[ResultRecordedPayload],
    failed: ProjectionRecord[ResultRecordedPayload],
    identity: str,
    actions: _Actions,
    observed: Set[EventId],
) -> bool:
    payload = candidate.payload
    failed_payload = failed.payload
    if (
        payload is None
        or failed_payload is None
        or payload.outcome is not ResultOutcome.SUCCESS
        or candidate.source_frontier <= failed.source_frontier
        or payload.action_id == failed_payload.action_id
    ):
        return False
    action = _command_action(candidate, actions, observed)
    if action is None:
        return False
    return command_identity(action.command) == identity or identity in success_certified_identities(
        action.command
    )


def retirement_witness(
    failed: ResultId, results: _Results, actions: _Actions, observed: Set[EventId]
) -> tuple[EventId, int] | None:
    """The source event and frontier of the earliest later pass that retires ``failed``."""

    identity = _failed_identity(failed, results, actions, observed)
    failed_record = results.get(failed)
    if identity is None or failed_record is None:
        return None
    best: ProjectionRecord[ResultRecordedPayload] | None = None
    for record in results.values():
        if (best is None or record.source_frontier < best.source_frontier) and _certifies(
            record, failed_record, identity, actions, observed
        ):
            best = record
    return None if best is None else (best.source_event_id, best.source_frontier)


def _with_failed_run(
    record: FindingProjectionRecord,
    failed: ResultId | None,
    results: _Results,
    actions: _Actions,
    observed: Set[EventId],
) -> FindingProjectionRecord:
    witness = None if failed is None else retirement_witness(failed, results, actions, observed)
    return replace(
        record,
        failed_run_result_id=failed,
        retired_by_event_id=None if witness is None else witness[0],
        retired_frontier=None if witness is None else witness[1],
    )


def on_finding_recorded(
    findings: dict[FindingId, FindingProjectionRecord],
    key: FindingId,
    results: _Results,
    actions: _Actions,
    observed: Set[EventId],
    observation_findings: Set[EventId],
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
    findings[key] = _with_failed_run(stamped, failed, results, actions, observed)


def on_observed_result(
    findings: dict[FindingId, FindingProjectionRecord],
    result_key: ResultId,
    results: _Results,
    actions: _Actions,
    observed: Set[EventId],
) -> None:
    """Fold one just-recorded hook-observed result into every open candidate.

    A failure may be the failed run of a finding recorded before it (the Codex outcome
    correction can land after the finding names the call); a success may retire a finding whose
    failed run it reruns. Anything else changes nothing.
    """

    new = results.get(result_key)
    if new is None or new.payload is None or new.source_event_id not in observed:
        return
    outcome = new.payload.outcome
    if outcome in _FAILED_OUTCOMES:
        for key, record in tuple(findings.items()):
            payload = record.payload
            if (
                payload is None
                or not record.observed_failed_command
                or record.failed_run_result_id is not None
            ):
                continue
            failed = failed_run_of(payload, results, actions, observed, through=new.source_frontier)
            if failed is not None:
                findings[key] = _with_failed_run(record, failed, results, actions, observed)
        return
    if outcome is not ResultOutcome.SUCCESS:
        return
    for key, record in tuple(findings.items()):
        failed = record.failed_run_result_id
        if record.payload is None or failed is None or record.retired_by_event_id is not None:
            continue
        identity = _failed_identity(failed, results, actions, observed)
        failed_record = results.get(failed)
        if (
            identity is not None
            and failed_record is not None
            and _certifies(new, failed_record, identity, actions, observed)
        ):
            findings[key] = replace(
                record,
                retired_by_event_id=new.source_event_id,
                retired_frontier=new.source_frontier,
            )


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
) -> None:
    """Re-derive every candidate's failed run and retirement after a redaction.

    An unreadable finding, failed run, action or passing run clears what depended on it, exactly
    as a full replay of the readable records would derive it.
    """

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
                )
            continue
        failed = _derived_failed_run(record, results, actions, observed)
        updated = _with_failed_run(record, failed, results, actions, observed)
        if updated != record:
            findings[key] = updated
