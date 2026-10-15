"""What a reviewer challenge is about, decided from recorded facts (issues #1042 and #1043).

FinishUP catches incomplete work; it is not a bug finder (ADR-040). tb4n4 measured the semantic arm:
of 79 reviewer findings, 34% were correctness opinions outside that frame, and 5
``action_without_result`` plus 4 premature "nothing implemented yet" findings were about FinishUP's own
process state although the reviewer instruction forbids both. On interleaved-vigenere S the
reviewer turned failures of the agent's own oversized stress runs into ``task_requirement_unmet``
and the agent spent forty minutes chasing a criterion no task stated.

The check asks two questions of every reviewer challenge before it can become a finding. Each
predicate here is pure: it reads only the frozen projection, the challenge's kind and its resolved
subject refs (the ``evt_``, ``obl_`` and ``clm_`` ids the check fenced), never the reviewer's words.
Each answers ``True`` only on positive evidence; anything unreadable or unknown answers ``False``,
so the challenge is kept as the reviewer gave it.

* ``finishup_process_state_only``: every subject is FinishUP's own capture or process record. Either the
  hook's observation of a call to one of FinishUP's own tools (the check in flight, a status poll), or,
  for ``action_without_result``, a hook-observed action: pairing a hook observation with its result
  is FinishUP's capture, never the agent's account.
* ``local_rule_owned`` (tb4n5 follow-up): an ``action_without_result`` or ``result_without_action``
  challenge whose cited records show only the pairing gap the local work-integrity rule decides
  over the whole ledger (an unpaired action, an orphan result, and their own plain output). Its
  copy duplicated the local finding (vigenere S, live-db S) or misplaced it (medical S cited the
  sibling command for "the engine edit has no linked result") and latched
  ``disputed_after_rebuttal`` while the local twin resolved. A challenge under that label that
  cites a claim, an obligation, a paired action or a failed run keeps its concern.
* ``agent_probe_only``: a ``task_requirement_unmet`` challenge whose only cited work is hook-observed
  command runs that are not the task's own declared verification (neither matching a requested
  command nor linked to one by the agent), while that declared verification is on record and
  holds (see the function for the exact predicate).

A "nothing implemented yet" challenge under a requirement kind cannot be told from a real unmet
requirement without reading the reviewer's words, so nothing here filters it: the plan-time ones go
with the review before the first edit (issue #1046), ``requested_item_never_attempted`` during work
in progress is dropped by the check (ADR-040 section 5), and the routine instruction says work not
yet started is not a defect.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Final

from finishup.domain.command_segments import requested_command_shape
from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    RequestedItemKind,
    ResultOutcome,
)
from finishup.domain.findings import FindingKind
from finishup.domain.finishup_tools import finishup_tool_spelling
from finishup.domain.values import EventId, EvidenceId, ObligationId
from finishup.kernel.observed_failures import observed_action_tool
from finishup.kernel.projections import ProjectionState
from finishup.kernel.task_facts import (
    PLANNED_VERIFICATION_FAILED_GAP,
    PLANNED_VERIFICATION_NOT_OBSERVED_GAP,
    PLANNED_VERIFICATION_OUTCOME_UNKNOWN_GAP,
    PLANNED_VERIFICATION_STALE_GAP,
    PLANNED_VERIFICATION_UNOBSERVABLE_GAP,
    PlannedCommand,
    acknowledged_obligation_ids,
    command_identity_key_registered,
    effective_obligations,
    observed_run_from_command,
    planned_match,
    requested_planned_command,
)

__all__ = [
    "LOCAL_RULE_OWNED_KINDS",
    "PLANNED_VERIFICATION_DOUBT_GAPS",
    "agent_probe_only",
    "finishup_process_state_only",
    "local_rule_owned",
]

# Task facts that say the declared verification does not hold on the record: it failed, was not
# observed, went stale after an edit, cannot be observed, or ran with an unknown outcome.
PLANNED_VERIFICATION_DOUBT_GAPS: Final = frozenset(
    {
        PLANNED_VERIFICATION_FAILED_GAP,
        PLANNED_VERIFICATION_NOT_OBSERVED_GAP,
        PLANNED_VERIFICATION_STALE_GAP,
        PLANNED_VERIFICATION_UNOBSERVABLE_GAP,
        PLANNED_VERIFICATION_OUTCOME_UNKNOWN_GAP,
    }
)


def _rows_by_event(
    projection: ProjectionState,
) -> tuple[
    Mapping[EventId, ActionRecordedPayload],
    Mapping[EventId, ActionRecordedPayload],
    Mapping[EventId, ActionRecordedPayload],
]:
    """Readable actions by their event, and the action each result or result-cited evidence answers."""

    actions: dict[EventId, ActionRecordedPayload] = {}
    for row in projection.actions.values():
        if row.payload is not None:
            actions[row.source_event_id] = row.payload
    results: dict[EventId, ActionRecordedPayload] = {}
    evidence_actions: dict[EvidenceId, ActionRecordedPayload] = {}
    for row in projection.results.values():
        payload = row.payload
        if payload is None:
            continue
        action = projection.actions.get(payload.action_id)
        if action is None or action.payload is None:
            continue
        results[row.source_event_id] = action.payload
        for cited in payload.evidence_refs:
            evidence_actions[cited] = action.payload
    evidence: dict[EventId, ActionRecordedPayload] = {}
    for key, row in projection.evidence.items():
        action = evidence_actions.get(key)
        if row.payload is not None and action is not None:
            evidence[row.source_event_id] = action
    return actions, results, evidence


def _finishup_own_call(action: ActionRecordedPayload) -> bool:
    tool = observed_action_tool(action.description)
    return tool is not None and finishup_tool_spelling(tool) is not None


def finishup_process_state_only(
    projection: ProjectionState,
    kind: FindingKind,
    subject_refs: Iterable[str],
    observed: frozenset[EventId],
) -> bool:
    """Whether every subject of a challenge is FinishUP's own capture or process record.

    ``observed`` are the hook-observed events of the frozen case (``observed_event_ids_from_coverage``):
    a description FinishUP can parse is trusted only on a service-stamped observation, never on an
    action the agent published. A subject counts when it is the observation of a call to one of
    FinishUP's own tools (or that call's result), or, for ``action_without_result`` only, any
    hook-observed action: the hook pairs an observed call with its result, so a missing result is
    a capture or in-flight state (the check call itself is always in flight), never an omission in
    the agent's account. A claim, an obligation, an agent-published record or any other observed
    work keeps the challenge.
    """

    refs = tuple(subject_refs)
    if not refs:
        return False
    actions, results, _evidence = _rows_by_event(projection)
    for ref in refs:
        event = EventId(ref) if ref.startswith("evt_") else None
        if event is None or event not in observed:
            return False
        action = actions.get(event)
        if action is not None:
            if _finishup_own_call(action):
                continue
            if kind is FindingKind.ACTION_WITHOUT_RESULT:
                continue
            return False
        answered = results.get(event)
        if answered is not None and _finishup_own_call(answered):
            continue
        return False
    return True


# The ledger relations the local work-integrity rules decide over the whole record (tb4n5 follow-up
# of #1042): an action no result names, and a result that names no action.
LOCAL_RULE_OWNED_KINDS: Final = frozenset(
    {FindingKind.ACTION_WITHOUT_RESULT, FindingKind.RESULT_WITHOUT_ACTION}
)


def local_rule_owned(
    projection: ProjectionState, kind: FindingKind, subject_refs: Iterable[str]
) -> bool:
    """Whether a challenge only restates a pairing gap the local rule owns (tb4n5).

    The label is never proof: a reviewer can file a false completion or an unrun verification
    under ``action_without_result``. So this answers ``True`` only when the cited records
    themselves show nothing but the pairing gap the local rule decides over the whole ledger:

    * ``action_without_result``: at least one cited event recorded a readable action that no
      readable result names (an unpaired action), and every cited event is such an action;
    * ``result_without_action``: at least one cited event recorded a readable, successful result
      whose action is absent, and every cited event is such a result;
    * either kind may also cite events of readable evidence that no claim and no result that did
      not succeed cites (the vigenere S shape: the run's own output beside it).

    Anything else keeps the challenge as the reviewer gave it: an action that already has a result
    (the concern is not the missing link), a claim or an obligation (a completion, requirement or
    planned-verification concern), a result or evidence of a run that did not succeed (a failure
    concern), a decision, or anything unreadable or unknown. The three tb4n5 shapes (vigenere,
    live-db, medical) cite only unpaired actions and their own output.
    """

    if kind not in LOCAL_RULE_OWNED_KINDS:
        return False
    refs = tuple(subject_refs)
    if not refs or any(not ref.startswith("evt_") for ref in refs):
        return False
    named = {
        row.payload.action_id
        for row in projection.results.values()
        if row.payload is not None and not row.redacted
    }
    unpaired_actions = {
        row.source_event_id
        for action, row in projection.actions.items()
        if row.payload is not None and not row.redacted and action not in named
    }
    orphan_results = {
        row.source_event_id
        for row in projection.results.values()
        if row.payload is not None
        and not row.redacted
        and row.payload.outcome is ResultOutcome.SUCCESS
        and (
            (action := projection.actions.get(row.payload.action_id)) is None
            or action.payload is None
        )
    }
    concerned: set[str] = set()
    for row in projection.results.values():
        if row.payload is not None and row.payload.outcome is not ResultOutcome.SUCCESS:
            concerned.update(str(item) for item in row.payload.evidence_refs)
    for claim in projection.claims.values():
        if claim.payload is not None:
            concerned.update(str(item) for item in claim.payload.supporting_refs)
    plain_evidence = {
        row.source_event_id
        for key, row in projection.evidence.items()
        if row.payload is not None and not row.redacted and str(key) not in concerned
    }
    relation = unpaired_actions if kind is FindingKind.ACTION_WITHOUT_RESULT else orphan_results
    events = {EventId(ref) for ref in refs}
    return bool(events & relation) and events <= relation | plain_evidence


def agent_probe_only(
    projection: ProjectionState,
    kind: FindingKind,
    subject_refs: Iterable[str],
    *,
    observed: frozenset[EventId],
    case_gap_codes: frozenset[str],
    blocked: frozenset[ObligationId] = frozenset(),
    linked: frozenset[EventId] | None = frozenset(),
) -> bool:
    """Whether a requirement challenge rests only on the agent's own probes (issue #1043).

    True exactly when all of these hold, each read from recorded facts:

    1. the challenge is ``task_requirement_unmet``;
    2. the task's own verification is on record: at least one effective obligation that is neither
       acknowledged as not done nor confirmed blocked requests a command, and the case carries none
       of the facts that would doubt it (``PLANNED_VERIFICATION_DOUBT_GAPS``: failed, not observed,
       stale after an edit, unobservable, outcome unknown), so every declared verification ran
       after the last edit and passed;
    3. the challenge cites at least one recorded run, and every recorded work subject is a
       hook-observed command run (the action, its result, or output evidence that result cites)
       that matches none of those requested commands and that the agent did not link to a
       requested command value: a run the agent chose beyond the task's declared verification.
       A linked run (PL6-3; ``linked`` holds its observed action events, from
       ``task_facts.agent_linked_run_events``) is the declared verification the task facts
       accept, never a run beyond it; ``None`` (links unreadable) answers ``False``. Obligations,
       claims and the plan or statement events it also cites are the requirement being judged,
       not evidence;
    4. the command-identity key is registered (observed commands are stored only as keyed
       commitments); without it nothing can be matched and the answer is ``False``.

    An edit, an agent-published action, a run FinishUP cannot match or any unreadable row keeps the
    challenge a task requirement. The predicate cannot see which files a run read (hook rows carry
    no command text or path), so a failing run of a task-supplied example the agent did not
    declare as verification is also routed; that residual is disclosed in ADR-040.
    """

    if kind is not FindingKind.TASK_REQUIREMENT_UNMET or case_gap_codes & (
        PLANNED_VERIFICATION_DOUBT_GAPS
    ):
        return False
    if linked is None or not command_identity_key_registered():
        return False
    acknowledged = acknowledged_obligation_ids(projection)
    planned: list[PlannedCommand] = []
    for obligation in effective_obligations(projection):
        if obligation in acknowledged or obligation in blocked:
            continue
        row = projection.obligations.get(obligation)
        if row is None or row.payload is None:
            continue
        for item in row.payload.requested_items:
            if (
                item.item_kind is RequestedItemKind.COMMAND
                and requested_command_shape(item.value) == "command"
            ):
                command = requested_planned_command(item.value)
                if command is None:
                    return False
                planned.append(command)
    if not planned:
        return False
    actions, results, evidence = _rows_by_event(projection)
    declared = {
        row.payload.action_id
        for row in projection.actions.values()
        if row.payload is not None and row.source_event_id in linked
    }
    runs = 0
    for ref in subject_refs:
        if ref.startswith(("obl_", "clm_")):
            continue
        if not ref.startswith("evt_"):
            return False
        event = EventId(ref)
        action = actions.get(event) or results.get(event) or evidence.get(event)
        if action is None:
            if event in observed or _is_work_event(projection, event):
                # Recorded work FinishUP cannot tie to a readable command run.
                return False
            # The plan, the task statement or another non-work record the challenge names.
            continue
        if (
            event not in observed
            or action.action_kind is not ActionKind.COMMAND
            or action.action_id in declared
        ):
            return False
        run = observed_run_from_command(action.command)
        if run is None or any(planned_match(run, command) is not None for command in planned):
            return False
        runs += 1
    return runs > 0


def _is_work_event(projection: ProjectionState, event: EventId) -> bool:
    """Whether *event* recorded an action, a result or evidence (readable or not)."""

    return any(
        row.source_event_id == event
        for rows in (projection.actions, projection.results, projection.evidence)
        for row in rows.values()
    )
