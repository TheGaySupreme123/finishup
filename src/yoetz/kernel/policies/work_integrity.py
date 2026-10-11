"""Local work-integrity policy pack."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final, cast

from yoetz.domain.events import (
    ActionKind,
    ClaimKind,
    ClaimRecordedPayload,
    ClaimRecordedPayloadV1_1,
    EvidenceKind,
    ObligationChangeKind,
    ObligationStatus,
    RequestedItem,
    RequestedItemKind,
    RequestedItemRole,
    ResponseDisposition,
    ResultOutcome,
)
from yoetz.domain.findings import FindingKind, FindingOrigin
from yoetz.domain.observation_selection import command_runner_class
from yoetz.domain.values import (
    EventId,
    EvidenceId,
    ObligationId,
    ResultId,
    SubjectStateRef,
    SubjectStateRelation,
    subject_state_relation,
)
from yoetz.kernel.claims import (
    claim_discloses_result,
    effective_claim_ids,
    effective_claim_items,
    result_is_relevant_to_claim,
)
from yoetz.kernel.command_attempts import attempted_items_for_obligation, value_in_attempted
from yoetz.kernel.deterministic_checks import (
    CALLER_DIGEST_PROVENANCE_GAPS,
    OBSERVED_FAILURE_LIVE_FACT,
    OBSERVED_VERIFICATION_ABSENT_FACT,
    OBSERVED_VERIFICATION_UNCITED_FACT,
    REQUESTED_OUTPUT_ABSENT_FACT,
    DeterministicAssessment,
    DeterministicCase,
    FindingBasisRef,
    FindingFact,
    FrozenSourceAvailability,
    PolicyPack,
    build_policy_assessment,
    policy_public_root,
    policy_source_availability,
)
from yoetz.kernel.observed_failures import (
    ObservedFailureState,
    observed_action_is_exploratory,
    observed_action_runner_class,
    observed_edit_counts,
    observed_event_ids_from_coverage,
    observed_failure_states,
)
from yoetz.kernel.plan_scope import current_plan_scope
from yoetz.kernel.policies.response_support import (
    BASE_RESPONSE_INADMISSIBLE_GAPS,
    WORK_RESPONSE_PRESENT_FACT,
    response_support_admissible,
)
from yoetz.kernel.task_facts import (
    STANDING_TASK_FACT_GAPS,
    acting_started,
    confirmed_blocked_obligation_ids,
    cooperative_event_ids_from_coverage,
    non_counting_edits_exempt,
    observed_planned_commands,
)
from yoetz.protocol.policy_packs import WORK_INTEGRITY_POLICY_ID, WORK_INTEGRITY_POLICY_VERSION

__all__ = [
    "WORK_INTEGRITY_FACT_CODES",
    "WORK_INTEGRITY_POLICY_ID",
    "WORK_INTEGRITY_POLICY_PACK",
    "WORK_INTEGRITY_POLICY_VERSION",
    "reportable_absent_outputs",
    "work_integrity_findings",
]

WORK_INTEGRITY_POLICY_PACK: Final = PolicyPack(
    WORK_INTEGRITY_POLICY_ID,
    WORK_INTEGRITY_POLICY_VERSION,
)
WORK_INTEGRITY_FACT_CODES: Final = frozenset(
    {
        "completion_claim_present",
        "open_obligation_present",
        "valid_waiver_absent",
        "requested_item_present",
        "linked_attempt_absent",
        "failed_result_present",
        OBSERVED_FAILURE_LIVE_FACT,
        "failure_disclosure_absent",
        "claim_present",
        "admissible_evidence_absent",
        "result_present",
        "linked_action_absent",
        "action_present",
        "linked_result_absent",
        "subsequent_unrelated_work_present",
        "state_comparison_available",
        "state_changed",
        "evidence_state_mismatch",
        "contradictory_claims_present",
        "resolution_absent",
        "unknown_event_present",
        "redaction_gap_present",
        "freshness_gap_present",
        "finding_response_present",
        "response_basis_insufficient",
        "response_state_stale",
        OBSERVED_VERIFICATION_UNCITED_FACT,
        OBSERVED_VERIFICATION_ABSENT_FACT,
        REQUESTED_OUTPUT_ABSENT_FACT,
    }
)
_COMMAND_ATTEMPT_UNCORROBORATED_GAP: Final = "command_attempt_uncorroborated"
# Hook-derived runner classes that read or inspect rather than verify (closed tokens; no
# command text is parsed here).
_NON_VERIFICATION_RUNNERS: Final = frozenset({"exploration", "vcs"})

_RULE_ORDER: Final = (
    FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
    FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED,
    FindingKind.FAILED_WORK_OMITTED,
    FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
    FindingKind.RESULT_WITHOUT_ACTION,
    FindingKind.ACTION_WITHOUT_RESULT,
    FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE,
    FindingKind.CONTRADICTORY_CLAIMS_UNRESOLVED,
    FindingKind.LEDGER_STALE_OR_INCOMPLETE,
    FindingKind.WEAK_OR_STALE_RESPONSE,
)
_WORK_RESPONSE_INADMISSIBLE_GAPS: Final = BASE_RESPONSE_INADMISSIBLE_GAPS | {
    "evidence_digest_subject_legacy_unknown"
}


def _ascii(value: str) -> bytes:
    return value.encode("ascii", errors="strict")


def _refs(values: Iterable[FindingBasisRef]) -> tuple[FindingBasisRef, ...]:
    return tuple(sorted(set(values), key=_ascii))


def _fact(code: str, *refs: FindingBasisRef) -> FindingFact:
    return FindingFact(code, _refs(refs))


def _coverage_admissible(case: DeterministicCase, ref: FindingBasisRef) -> bool:
    coverage = case.coverage_by_ref.get(ref)
    if coverage is None:
        return False
    return not _WORK_RESPONSE_INADMISSIBLE_GAPS & set(coverage.known_gaps)


def _claim_support_is_admissible(
    case: DeterministicCase,
    claim_kind: ClaimKind,
    claim_state: SubjectStateRef | None,
    ref: FindingBasisRef,
) -> bool:
    if ref not in case.allowed_ids or not _coverage_admissible(case, ref):
        return False
    if ref.startswith("evd_"):
        record = case.projection.evidence.get(EvidenceId(ref))
        if record is None or record.payload is None:
            return False
        return (
            subject_state_relation(record.payload.subject_state, claim_state)
            is not SubjectStateRelation.DIFFERENT
        )
    if ref.startswith("res_"):
        record = case.projection.results.get(ResultId(ref))
        if record is None or record.payload is None:
            return False
        if (
            claim_kind is ClaimKind.COMPLETION
            and record.payload.outcome is not ResultOutcome.SUCCESS
        ):
            return False
        return (
            subject_state_relation(record.payload.subject_state, claim_state)
            is not SubjectStateRelation.DIFFERENT
        )
    if ref.startswith("obl_"):
        record = case.projection.obligations.get(ObligationId(ref))
        if record is None or record.payload is None:
            return False
        return (
            claim_kind is not ClaimKind.COMPLETION
            or record.payload.status is ObligationStatus.RESOLVED
            or record.plan_change is ObligationChangeKind.WAIVED
        )
    return False


def _active_requested_obligations(case: DeterministicCase) -> frozenset[ObligationId]:
    scope = current_plan_scope(case.projection.plans, case.projection.coverage_gaps)
    if scope.effective_obligation_refs is None:
        # The frozen case already carries the plan redaction/unknown-event gap. Do not invent a
        # partial obligation set from whichever readable plan fragments happen to remain.
        return frozenset()
    return frozenset(
        obligation
        for obligation in scope.effective_obligation_refs
        if (record := case.projection.obligations.get(obligation)) is not None
        and record.payload is not None
    )


def _action_subject_key(
    obligation_refs: tuple[str, ...],
    attempted_items: tuple[str, ...],
) -> tuple[str, tuple[str, ...]] | None:
    if obligation_refs:
        return ("obligations", obligation_refs)
    if attempted_items:
        return ("requested_items", attempted_items)
    return None


def _keys_are_disjoint(
    left: tuple[str, frozenset[str]],
    right: tuple[str, tuple[str, ...]] | None,
) -> bool:
    return right is not None and left[0] == right[0] and left[1].isdisjoint(right[1])


def _response_support_admissible(
    case: DeterministicCase,
    refs: tuple[EvidenceId | ResultId, ...],
) -> bool:
    return response_support_admissible(
        case,
        refs,
        inadmissible_gaps=_WORK_RESPONSE_INADMISSIBLE_GAPS,
    )


def _completion_findings(case: DeterministicCase) -> list[DeterministicAssessment]:
    output: list[DeterministicAssessment] = []
    for claim_id, claim_record in effective_claim_items(case.projection):
        claim = claim_record.payload
        if claim is None or claim.claim_kind is not ClaimKind.COMPLETION:
            continue
        for obligation_ref in claim.obligation_refs:
            obligation_record = case.projection.obligations.get(obligation_ref)
            if obligation_record is None or obligation_record.payload is None:
                continue
            if (
                # acknowledged_not_done (#1002) is not resolved: treated like open here.
                obligation_record.payload.status is ObligationStatus.RESOLVED
                or obligation_record.plan_change is ObligationChangeKind.WAIVED
            ):
                continue
            subjects = _refs((claim_id, obligation_ref))
            output.append(
                build_policy_assessment(
                    case,
                    WORK_INTEGRITY_POLICY_PACK,
                    FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
                    subjects,
                    (
                        _fact("completion_claim_present", claim_id),
                        _fact("open_obligation_present", obligation_ref),
                    ),
                    (_fact("valid_waiver_absent", claim_id, obligation_ref),),
                )
            )
    return output


def _requested_item_findings(
    case: DeterministicCase,
    absent_outputs: frozenset[tuple[ObligationId, int]] = frozenset(),
) -> list[DeterministicAssessment]:
    """Requested items with no attempt once work began, or requested files that do not exist.

    Before the agent has started acting (an edit, a published action, or an observed command
    other than exploration or version control) an unattempted item is the plan, not an omission,
    so it raises nothing (#977, TB4: 86% of all findings were this plan-stage notice).
    ``absent_outputs`` comes from the check-time workspace read: a requested file that does not
    exist is reported whatever was published about it, because naming a file in
    ``attempted_items`` does not create it, but only once acting on that obligation has started
    (an edit, command or other non-research action linked to it) or a completion claim stands
    (tb4n1 E4). Each check re-reads the workspace, so the fact clears as soon as the file exists,
    whatever the observation coverage. Obligations a *confirmed* blocker names are disclosed
    through their blocker gap instead; a blocker the agent only claimed suppresses nothing until
    a later decision confirms it (#985).
    """

    output: list[DeterministicAssessment] = []
    started = acting_started(
        case.projection,
        observed_event_ids_from_coverage(case.coverage_by_ref),
        cooperative_event_ids_from_coverage(case.coverage_by_ref),
    )
    # The case's task-fact markers carry the confirmation rule (it needs the publish batches).
    blocked = confirmed_blocked_obligation_ids((gap.code, gap.subject_refs) for gap in case.gaps)
    matched_commands: frozenset[str] | None = None
    for obligation_ref in sorted(_active_requested_obligations(case), key=_ascii):
        record = case.projection.obligations[obligation_ref]
        payload = record.payload
        if (
            payload is None
            or obligation_ref in blocked
            # #997: the agent acknowledged it as not done; the receipt discloses that instead.
            or payload.status is ObligationStatus.ACKNOWLEDGED_NOT_DONE
        ):
            continue
        attempted = attempted_items_for_obligation(case.projection, obligation_ref)
        if matched_commands is None:
            # ADR-045: a hook-observed run of a planned command is an attempt, however the agent
            # published (or did not publish) it; computed once per case.
            matched_commands = observed_planned_commands(
                case.projection,
                observed_event_ids_from_coverage(case.coverage_by_ref),
                cooperative_event_ids_from_coverage(case.coverage_by_ref),
                {
                    item.value
                    for other in _active_requested_obligations(case)
                    if (other_payload := case.projection.obligations[other].payload) is not None
                    for item in other_payload.requested_items
                    if item.item_kind is RequestedItemKind.COMMAND
                },
            )
        # tb4n1 E4: the pre-work check the guidance asks for found every requested output absent
        # (48 of 68 first findings), because the file obviously does not exist yet. An absent
        # output is reported once acting on that obligation has started, or once a completion
        # claim stands; before then it is the plan, exactly like an unattempted item.
        reportable = _completion_claim_covers(case, obligation_ref) or (
            started and _obligation_acted_on(case, obligation_ref)
        )
        # tb4n2 E4 (P1-7): an item the obligation only reads (``role: input``) is never "not
        # attempted", and "never attempted" waits for work on *this* obligation (or a completion
        # claim naming it), never for any action anywhere in the task.
        unattempted = reportable and any(
            not _item_attempted(item, attempted, matched_commands)
            for item in payload.requested_items
            if getattr(item, "role", None) is not RequestedItemRole.INPUT
        )
        absent = reportable and any(
            (obligation_ref, index) in absent_outputs
            for index in range(len(payload.requested_items))
        )
        if not unattempted and not absent:
            continue
        observed = [_fact("requested_item_present", obligation_ref)]
        if absent:
            observed.append(_fact(REQUESTED_OUTPUT_ABSENT_FACT, obligation_ref))
        output.append(
            build_policy_assessment(
                case,
                WORK_INTEGRITY_POLICY_PACK,
                FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED,
                (obligation_ref,),
                tuple(observed),
                (_fact("linked_attempt_absent", obligation_ref),) if unattempted else (),
            )
        )
    return output


_NON_PRODUCING_ACTIONS: Final = frozenset({ActionKind.RESEARCH, ActionKind.REVIEW})


def _item_attempted(
    item: RequestedItem, attempted: frozenset[str], matched_commands: frozenset[str]
) -> bool:
    """Whether one requested item was attempted (ADR-045): named, spelled alike, or observed run.

    A value named in ``attempted_items`` counts exactly as before. A file or directory counts when
    the agent named the same path in another spelling (``out/x.log`` for ``/app/out/x.log``), and
    a command counts when a hook-observed run matched it (exactly, up to wrappers, or by its
    leading arguments or flags): the agent ran it, whether or not it said so.
    """

    if item.value in attempted:
        return True
    if item.item_kind is RequestedItemKind.COMMAND:
        return item.value in matched_commands
    if item.item_kind in {RequestedItemKind.FILE, RequestedItemKind.DIRECTORY}:
        return value_in_attempted(item.value, attempted)
    return False


def reportable_absent_outputs(
    case: DeterministicCase,
    absent_outputs: frozenset[tuple[ObligationId, int]],
) -> frozenset[tuple[ObligationId, int]]:
    """The absent requested outputs this case reports: those whose obligation work has begun.

    The same rule ``requested_item_never_attempted`` applies (tb4n1 E4), shared so the AI-powered
    review packet's ``requested_output_absent`` task fact never runs ahead of the finding: a
    completion claim covering the obligation, or acting started and a cooperative action works on
    that obligation.
    """

    if not absent_outputs:
        return absent_outputs
    started = acting_started(
        case.projection,
        observed_event_ids_from_coverage(case.coverage_by_ref),
        cooperative_event_ids_from_coverage(case.coverage_by_ref),
    )
    return frozenset(
        pair
        for pair in absent_outputs
        if _completion_claim_covers(case, pair[0])
        or (started and _obligation_acted_on(case, pair[0]))
    )


def _completion_claim_covers(case: DeterministicCase, obligation_ref: ObligationId) -> bool:
    """Whether an effective completion claim names this obligation, or claims the whole task."""

    return any(
        record.payload is not None
        and record.payload.claim_kind is ClaimKind.COMPLETION
        and (not record.payload.obligation_refs or obligation_ref in record.payload.obligation_refs)
        for _, record in effective_claim_items(case.projection)
    )


def _obligation_acted_on(case: DeterministicCase, obligation_ref: ObligationId) -> bool:
    """Whether a recorded action works on this obligation, not merely investigates it.

    Only the agent's own (cooperative) actions count; hook-observed actions name no obligation.
    Attribution follows ``attempted_items_for_obligation``: an action with no ``obligation_refs``
    is global and covers every obligation; one that names obligations covers only those. Only an
    ``edit``, ``command`` or ``other`` action counts. Research and review actions read; they never
    create a requested file.
    """

    cooperative = cooperative_event_ids_from_coverage(case.coverage_by_ref)
    payload = case.projection.obligations[obligation_ref].payload
    for record in case.projection.actions.values():
        action = record.payload
        if (
            action is None
            or action.action_kind in _NON_PRODUCING_ACTIONS
            or record.source_event_id not in cooperative
        ):
            # A hook-observed action carries no obligation_refs, so it would read as global and
            # mark every obligation acted on after any `ls` (adversarial review of E4).
            continue
        if obligation_ref in action.obligation_refs:
            return True
        if not action.obligation_refs and payload is not None:
            # ADR-045 (tb4n3 lake S): a global action works on the obligations whose items it
            # names, not on every obligation: one untargeted command published while the real
            # run was still going made every absent output reportable mid-work.
            if any(
                value_in_attempted(item.value, action.attempted_items)
                for item in payload.requested_items
            ):
                return True
    return False


def _failed_work_findings(case: DeterministicCase) -> list[DeterministicAssessment]:
    output: list[DeterministicAssessment] = []
    observed = observed_event_ids_from_coverage(case.coverage_by_ref)
    for claim_id, claim_record in effective_claim_items(case.projection):
        claim = claim_record.payload
        if claim is None or claim.claim_kind is not ClaimKind.COMPLETION:
            continue
        # One shared reading (#909): only a later run of the same keyed command can supersede a
        # hook-observed failure. An edit changes the state under test but proves no covering rerun.
        states = observed_failure_states(
            case.projection, observed, through=claim_record.source_frontier
        )
        for result_id, record in case.projection.results.items():
            if (
                record.payload is None
                or record.payload.outcome not in {ResultOutcome.FAILURE, ResultOutcome.PARTIAL}
                or not result_is_relevant_to_claim(case.projection, claim_record, result_id)
                or claim_discloses_result(claim, result_id)
            ):
                continue
            state = states.get(result_id)
            action = case.projection.actions.get(record.payload.action_id)
            if state is not None and action is not None and action.payload is not None:
                if action.source_event_id in observed and observed_action_is_exploratory(
                    action.payload
                ):
                    # A known read/exploration command is useful context but is not a required
                    # validation result. Unknown command classes remain limiting.
                    continue
            if state is not None and state is not ObservedFailureState.LIVE:
                continue
            observed_facts = [_fact("failed_result_present", result_id)]
            if state is ObservedFailureState.LIVE:
                # Name the observed run structurally (its action and result ids) so the agent can
                # find its tool, order, command commitment and exit status in status results.
                run_refs: list[FindingBasisRef] = [result_id]
                action_ref = record.payload.action_id
                if action_ref in case.allowed_ids:
                    run_refs.append(action_ref)
                observed_facts.append(_fact(OBSERVED_FAILURE_LIVE_FACT, *run_refs))
            output.append(
                build_policy_assessment(
                    case,
                    WORK_INTEGRITY_POLICY_PACK,
                    FindingKind.FAILED_WORK_OMITTED,
                    _refs((claim_id, policy_public_root(case, result_id))),
                    tuple(observed_facts),
                    (_fact("failure_disclosure_absent", claim_id, result_id),),
                    source_availability=policy_source_availability(case, (result_id,)),
                )
            )
    return output


def _unsupported_claim_findings(case: DeterministicCase) -> list[DeterministicAssessment]:
    output: list[DeterministicAssessment] = []
    for claim_id, record in effective_claim_items(case.projection):
        claim = record.payload
        if claim is None:
            continue
        support_refs = cast(tuple[FindingBasisRef, ...], claim.supporting_refs)
        if any(
            _claim_support_is_admissible(
                case,
                claim.claim_kind,
                claim.subject_state,
                ref,
            )
            for ref in support_refs
        ):
            continue
        availability = (
            FrozenSourceAvailability.NOT_RECORDED
            if not support_refs
            else policy_source_availability(case, support_refs)
        )
        output.append(
            build_policy_assessment(
                case,
                WORK_INTEGRITY_POLICY_PACK,
                FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
                (claim_id,),
                (_fact("claim_present", claim_id),),
                (_fact("admissible_evidence_absent", claim_id),),
                source_availability=availability,
            )
        )
    reported = {assessment.candidate.subject_refs for assessment in output}
    output.extend(
        assessment
        for assessment in _uncorroborated_completion_findings(case)
        if assessment.candidate.subject_refs not in reported
    )
    return output


def _observed_verification_facts(
    case: DeterministicCase,
) -> tuple[int | None, bool, dict[str, int]]:
    """Return the latest observed edit frontier, whether a verification ran, and its refs.

    Only service-stamped hook observations count (ADR-022): a cooperative edit or result never
    stands in for an observed one. A verification run is a hook-observed command result whose
    host-derived runner class is not ``exploration`` or ``vcs``; an unclassified command counts,
    so the rule never fires merely because a host omitted the class.

    Corroboration is verification-class only (TB4 pilot): the run's own result, or captured
    output that result links, at the run's frontier. Captured output of an edit, of an
    exploration or VCS command, or a standalone capture no run links never corroborates. A run
    whose host stated no outcome (a long Codex run that outlived its yield) still corroborates
    that it ran after the edit, but only a run with a recorded outcome makes the rule apply.
    """

    observed = observed_event_ids_from_coverage(case.coverage_by_ref)
    exempt = non_counting_edits_exempt(case.projection)
    latest_edit: int | None = None
    for action in case.projection.actions.values():
        payload = action.payload
        if (
            payload is not None
            and action.source_event_id in observed
            and payload.action_kind is ActionKind.EDIT
            # A scratch or Yoetz-owned write (a saved receipt) changes nothing a claim's
            # verification covered (ADR-042, tb4n2 R4: cad S, lake D).
            and observed_edit_counts(payload.description, exempt)
        ):
            latest_edit = max(latest_edit or 0, action.source_frontier)
    runs: dict[str, int] = {}
    verification_observed = False
    for result_ref, result in case.projection.results.items():
        payload = result.payload
        if payload is None or result.source_event_id not in observed:
            continue
        action = case.projection.actions.get(payload.action_id)
        if (
            action is None
            or action.payload is None
            or action.source_event_id not in observed
            or action.payload.action_kind is not ActionKind.COMMAND
            or observed_action_runner_class(action.payload.description) in _NON_VERIFICATION_RUNNERS
        ):
            continue
        runs[str(result_ref)] = result.source_frontier
        # Only an observed edit or a verification run with a recorded outcome makes the rule
        # apply; an outcome-less run corroborates but never triggers the rule on its own.
        verification_observed = (
            verification_observed or payload.outcome is not ResultOutcome.UNKNOWN
        )
        for evidence_ref in payload.evidence_refs:
            runs[str(evidence_ref)] = max(runs.get(str(evidence_ref), 0), result.source_frontier)
    return latest_edit, verification_observed, runs


def _uncorroborated_completion_findings(case: DeterministicCase) -> list[DeterministicAssessment]:
    """A completion claim must cite a verification made after the latest observed edit.

    Applies only when hook observation recorded an edit or a verification run in this task, so a
    host without hooks keeps its ordinary coverage disclosure instead of an unanswerable finding.
    The support chain is the claim's ``supporting_refs`` and ``limitation_refs`` plus the
    resolution evidence of the resolved obligations it names: an honestly disclosed failing run is
    corroboration too. Self-generated evidence stays admissible (#977 item 5, ADR-033; tb4n1 E7):
    a hook-observed verification run, or the agent's own admissible verification record (a
    ``command`` result or ``test_result``/``command_output`` evidence) published after the latest
    observed edit, satisfies the rule. Only a chain whose every verification predates that edit,
    or that cites none, is reported. A rerun of the check changes none of these relations.
    """

    latest_edit, verification_observed, runs = _observed_verification_facts(case)
    if latest_edit is None and not verification_observed:
        return []
    observed = observed_event_ids_from_coverage(case.coverage_by_ref)
    after = latest_edit or 0
    output: list[DeterministicAssessment] = []
    for claim_id, record in effective_claim_items(case.projection):
        claim = record.payload
        if claim is None or claim.claim_kind is not ClaimKind.COMPLETION:
            continue
        chain: set[str] = {*claim.supporting_refs}
        if type(claim) is ClaimRecordedPayloadV1_1:
            chain.update(claim.limitation_refs)
        for obligation_ref in claim.obligation_refs:
            obligation = case.projection.obligations.get(obligation_ref)
            if obligation is not None and obligation.payload is not None:
                chain.update(obligation.payload.resolution_evidence_refs)
        if any(runs.get(ref, -1) > after for ref in chain):
            continue
        if any(
            _self_published_verification_after(case, claim, ref, after, observed) for ref in chain
        ):
            continue
        output.append(
            build_policy_assessment(
                case,
                WORK_INTEGRITY_POLICY_PACK,
                FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
                (claim_id,),
                (_fact(OBSERVED_VERIFICATION_UNCITED_FACT, claim_id),),
                (_fact(OBSERVED_VERIFICATION_ABSENT_FACT, claim_id),),
            )
        )
    return output


_SELF_VERIFICATION_EVIDENCE: Final = frozenset(
    {EvidenceKind.TEST_RESULT, EvidenceKind.COMMAND_OUTPUT}
)


def _self_published_verification_after(
    case: DeterministicCase,
    claim: ClaimRecordedPayload,
    ref: str,
    after: int,
    observed: frozenset[EventId],
) -> bool:
    """Whether ``ref`` is the agent's own verification record published after frontier ``after``.

    Hook-observed records keep their verification-class rule in ``_observed_verification_facts``;
    this admits only cooperative records: a ``command`` action's result (a disclosed failing one
    included) or ``test_result``/``command_output`` evidence, admissible for the claim.
    """

    support = cast(FindingBasisRef, ref)
    admissible = _claim_support_is_admissible(case, claim.claim_kind, claim.subject_state, support)
    if ref.startswith("evd_"):
        evidence = case.projection.evidence.get(EvidenceId(ref))
        return (
            admissible
            and evidence is not None
            and evidence.payload is not None
            and evidence.source_event_id not in observed
            and evidence.payload.evidence_kind in _SELF_VERIFICATION_EVIDENCE
            and evidence.source_frontier > after
        )
    if ref.startswith("res_"):
        result = case.projection.results.get(ResultId(ref))
        if (
            result is None
            or result.payload is None
            or result.source_event_id in observed
            or result.source_frontier <= after
            or not (admissible or _is_limitation(claim, ref))
        ):
            return False
        action = case.projection.actions.get(result.payload.action_id)
        if action is None or action.payload is None:
            return False
        command = action.payload.command
        # The same verification-class rule as for observed runs: a published exploration or VCS
        # command (`ls`, `git status`) verifies nothing (adversarial review of E7).
        return (
            action.payload.action_kind is ActionKind.COMMAND
            and command is not None
            and command_runner_class({"command": command}) not in _NON_VERIFICATION_RUNNERS
        )
    return False


def _is_limitation(claim: ClaimRecordedPayload, ref: str) -> bool:
    return type(claim) is ClaimRecordedPayloadV1_1 and ref in claim.limitation_refs


def _orphan_result_findings(case: DeterministicCase) -> list[DeterministicAssessment]:
    output: list[DeterministicAssessment] = []
    for result_id, record in case.projection.results.items():
        result = record.payload
        if result is None:
            continue
        action = case.projection.actions.get(result.action_id)
        if action is not None and action.payload is not None:
            continue
        output.append(
            build_policy_assessment(
                case,
                WORK_INTEGRITY_POLICY_PACK,
                FindingKind.RESULT_WITHOUT_ACTION,
                (policy_public_root(case, result_id),),
                (_fact("result_present", result_id),),
                (_fact("linked_action_absent", result_id),),
            )
        )
    return output


def _unresolved_action_findings(case: DeterministicCase) -> list[DeterministicAssessment]:
    linked_actions = {
        record.payload.action_id
        for record in case.projection.results.values()
        if record.payload is not None
    }
    actions = tuple(
        sorted(
            (
                (action_id, record)
                for action_id, record in case.projection.actions.items()
                if record.payload is not None
            ),
            key=lambda item: (item[1].source_frontier, _ascii(item[0])),
        )
    )
    output: list[DeterministicAssessment] = []
    for action_id, record in actions:
        action = record.payload
        if action is None or action_id in linked_actions:
            continue
        subjects = _action_subject_key(action.obligation_refs, action.attempted_items)
        if subjects is None:
            continue
        # Reuse the later action's tuple instead of rebuilding its set for every pair.
        key = (subjects[0], frozenset(subjects[1]))
        later = tuple(
            later_id
            for later_id, later_record in actions
            if later_record.source_frontier > record.source_frontier
            and later_record.payload is not None
            and _keys_are_disjoint(
                key,
                _action_subject_key(
                    later_record.payload.obligation_refs,
                    later_record.payload.attempted_items,
                ),
            )
        )
        if not later:
            continue
        output.append(
            build_policy_assessment(
                case,
                WORK_INTEGRITY_POLICY_PACK,
                FindingKind.ACTION_WITHOUT_RESULT,
                (policy_public_root(case, action_id),),
                (
                    _fact("action_present", action_id),
                    _fact("subsequent_unrelated_work_present", action_id, *later),
                ),
                (_fact("linked_result_absent", action_id),),
            )
        )
    return output


def _state_pairs(
    case: DeterministicCase,
) -> tuple[tuple[EvidenceId, FindingBasisRef, SubjectStateRef, SubjectStateRef], ...]:
    pairs: set[tuple[EvidenceId, FindingBasisRef, SubjectStateRef, SubjectStateRef]] = set()
    for claim_id, record in effective_claim_items(case.projection):
        claim = record.payload
        if claim is None or claim.subject_state is None:
            continue
        for support in claim.supporting_refs:
            if support.startswith("evd_"):
                evidence = case.projection.evidence.get(EvidenceId(support))
                if (
                    evidence is not None
                    and evidence.payload is not None
                    and evidence.payload.subject_state is not None
                ):
                    pairs.add(
                        (
                            EvidenceId(support),
                            claim_id,
                            evidence.payload.subject_state,
                            claim.subject_state,
                        )
                    )
    for result_id, record in case.projection.results.items():
        result = record.payload
        if result is None or result.subject_state is None:
            continue
        for evidence_id in result.evidence_refs:
            evidence = case.projection.evidence.get(evidence_id)
            if (
                evidence is not None
                and evidence.payload is not None
                and evidence.payload.subject_state is not None
            ):
                pairs.add(
                    (evidence_id, result_id, evidence.payload.subject_state, result.subject_state)
                )
    return tuple(sorted(pairs, key=lambda item: (_ascii(item[0]), _ascii(item[1]))))


def _stale_evidence_findings(case: DeterministicCase) -> list[DeterministicAssessment]:
    output: list[DeterministicAssessment] = []
    for evidence_id, checked_ref, evidence_state, checked_state in _state_pairs(case):
        relation = subject_state_relation(evidence_state, checked_state)
        if relation is not SubjectStateRelation.DIFFERENT:
            continue
        fact_refs = _refs((evidence_id, checked_ref))
        output.append(
            build_policy_assessment(
                case,
                WORK_INTEGRITY_POLICY_PACK,
                FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE,
                _refs(
                    (
                        policy_public_root(case, evidence_id),
                        policy_public_root(case, checked_ref),
                    )
                ),
                (
                    FindingFact("state_comparison_available", fact_refs),
                    FindingFact("state_changed", fact_refs),
                    FindingFact("evidence_state_mismatch", fact_refs),
                ),
                subject_state_relation=relation,
                source_availability=policy_source_availability(case, fact_refs),
            )
        )
    return output


def _contradiction_findings(case: DeterministicCase) -> list[DeterministicAssessment]:
    output: list[DeterministicAssessment] = []
    effective = effective_claim_ids(case.projection)
    for key in sorted(
        case.projection.contradictions,
        key=lambda item: (_ascii(item.disputing_claim_id), _ascii(item.disputed_ref)),
    ):
        if key.disputing_claim_id not in effective:
            continue
        refs = _refs((key.disputing_claim_id, key.disputed_ref))
        if any(ref not in case.allowed_ids for ref in refs):
            continue
        output.append(
            build_policy_assessment(
                case,
                WORK_INTEGRITY_POLICY_PACK,
                FindingKind.CONTRADICTORY_CLAIMS_UNRESOLVED,
                refs,
                (FindingFact("contradictory_claims_present", refs),),
                (FindingFact("resolution_absent", refs),),
            )
        )
    return output


def _ledger_finding(case: DeterministicCase) -> list[DeterministicAssessment]:
    classes: dict[str, set[FindingBasisRef]] = {
        "unknown_event_present": set(),
        "redaction_gap_present": set(),
        "freshness_gap_present": set(),
    }
    for gap in case.gaps:
        if gap.code in CALLER_DIGEST_PROVENANCE_GAPS:
            # A caller-asserted digest the service did not verify is a disclosed provenance
            # label, not a ledger defect: it stays in case coverage and the receipt names it once
            # with a count, but no agent action can change it, so it never becomes a finding
            # subject whose growth would mint a new issue on every publication (issue #912).
            continue
        if gap.code in STANDING_TASK_FACT_GAPS:
            # A standing task fact (#977): an obligation a recorded blocker names, or a planned
            # verification whose outcome is unknown or unobservable. It is a disclosure classified
            # in GAP_CLASSIFICATION, not a stale ledger. As this informational finding it also
            # contradicted the check's own completeness (standing facts do not make a check
            # coverage-incomplete) and failed the check internally (invalid_ranked_findings).
            # Task-wide standing facts carry no subject and never reached a finding here.
            continue
        if gap.code == _COMMAND_ATTEMPT_UNCORROBORATED_GAP:
            # Same principle (TB4 pilot): a hook records a keyed commitment instead of command
            # text, so a requested command item can never be byte-compared with the observed run.
            # Nothing the agent publishes changes that; the gap stays in case coverage and on the
            # receipt as a standing limitation, never a finding an honest agent cannot clear.
            # ``command_attempt_mismatch`` is actionable and keeps its finding.
            continue
        if gap.code == "unknown_event":
            fact_code = "unknown_event_present"
        elif gap.code in {
            "redacted_event",
            "redacted_object",
            "event_payload_unavailable",
            "captured_object_unavailable",
        }:
            fact_code = "redaction_gap_present"
        else:
            fact_code = "freshness_gap_present"
        classes[fact_code].update(gap.subject_refs)
    observed = tuple(
        _fact(code, *refs) for code, values in classes.items() if (refs := _refs(values))
    )
    subjects = _refs(ref for fact in observed for ref in fact.subject_refs)
    if not subjects:
        return []
    if classes["redaction_gap_present"]:
        redaction_codes = {gap.code for gap in case.gaps if gap.subject_refs}
        availability = (
            FrozenSourceAvailability.REDACTED_AT_SOURCE
            if redaction_codes & {"redacted_event", "redacted_object"}
            else FrozenSourceAvailability.UNAVAILABLE_AT_FREEZE
        )
    elif classes["unknown_event_present"] or classes["freshness_gap_present"]:
        availability = FrozenSourceAvailability.NOT_RECORDED
    else:
        availability = FrozenSourceAvailability.AVAILABLE
    return [
        build_policy_assessment(
            case,
            WORK_INTEGRITY_POLICY_PACK,
            FindingKind.LEDGER_STALE_OR_INCOMPLETE,
            subjects,
            observed,
            source_availability=availability,
        )
    ]


def _response_findings(case: DeterministicCase) -> list[DeterministicAssessment]:
    output: list[DeterministicAssessment] = []
    for finding_id, response_record in case.projection.responses.items():
        response = response_record.payload
        finding_record = case.projection.findings.get(finding_id)
        if (
            response is None
            # A provenance dispute contests the finding's authorship/premise. It remains visible
            # on the receipt but is not a weak evidence-free rejection.
            or response.disposition
            not in {ResponseDisposition.REJECTED, ResponseDisposition.WAIVED}
            or finding_record is None
            or finding_record.payload is None
            # An AI-powered finding is advisory: rejecting a reviewer false positive without
            # evidence must not mint a new local, receipt-blocking finding. The later review
            # judges that rejection; research-evidence applies the same filter (issue #905).
            or finding_record.payload.origin is not FindingOrigin.DETERMINISTIC
        ):
            continue
        finding = finding_record.payload
        # A response answers the finding at the frontier that carries the finding's own record,
        # which necessarily follows the subject the check tested. Only a response aimed at a state
        # older than that subject answers something the finding was never about.
        stale = response.finding_frontier.sequence < finding.subject_frontier.sequence
        insufficient = not _response_support_admissible(case, response.evidence_refs)
        # This pack stays a closed rule table: it never inspects whether another pack would also
        # report this response. A current unsupported rejection of a local finding overlaps
        # research-evidence's questionable_finding_rejection, and the composition layer collapses
        # that overlap once it knows which packs actually ran.
        if not stale and not insufficient:
            continue
        if any(ref not in case.allowed_ids for ref in finding.subject_refs):
            continue
        response_event = response_record.source_event_id
        evidence_refs = tuple(ref for ref in response.evidence_refs if ref in case.allowed_ids)
        present_refs = _refs((finding_id, response_event, *evidence_refs))
        observed: list[FindingFact] = [FindingFact(WORK_RESPONSE_PRESENT_FACT, present_refs)]
        missing: list[FindingFact] = []
        if stale:
            observed.append(_fact("response_state_stale", finding_id, response_event))
        if insufficient:
            missing.append(_fact("response_basis_insufficient", finding_id, response_event))
        compared = _refs(evidence_refs)
        output.append(
            build_policy_assessment(
                case,
                WORK_INTEGRITY_POLICY_PACK,
                FindingKind.WEAK_OR_STALE_RESPONSE,
                finding.subject_refs,
                tuple(observed),
                tuple(missing),
                source_availability=(
                    policy_source_availability(case, compared)
                    if compared
                    else FrozenSourceAvailability.AVAILABLE
                ),
            )
        )
    return output


def work_integrity_findings(
    case: DeterministicCase,
    *,
    absent_outputs: frozenset[tuple[ObligationId, int]] = frozenset(),
) -> tuple[DeterministicAssessment, ...]:
    """Evaluate the closed work-integrity rule table without I/O.

    ``absent_outputs`` is the one check-time input that is not in the case: the requested files
    the application's metadata-only workspace read found absent (#977). The default reads none.
    """

    if type(case) is not DeterministicCase:
        raise ValueError("policy_wiring_invalid")
    by_rule = (
        _completion_findings(case),
        _requested_item_findings(case, absent_outputs),
        _failed_work_findings(case),
        _unsupported_claim_findings(case),
        _orphan_result_findings(case),
        _unresolved_action_findings(case),
        _stale_evidence_findings(case),
        _contradiction_findings(case),
        _ledger_finding(case),
        _response_findings(case),
    )
    if len(by_rule) != len(_RULE_ORDER):
        raise ValueError("policy_wiring_invalid")
    output: list[DeterministicAssessment] = []
    for kind, assessments in zip(_RULE_ORDER, by_rule, strict=True):
        deduped: dict[tuple[str, ...], DeterministicAssessment] = {}
        for assessment in assessments:
            if assessment.candidate.kind is not kind:
                raise ValueError("policy_wiring_invalid")
            key = tuple(assessment.candidate.subject_refs)
            if key in deduped:
                if deduped[key] != assessment:
                    raise ValueError("policy_wiring_invalid")
                continue
            deduped[key] = assessment
        output.extend(
            deduped[key]
            for key in sorted(deduped, key=lambda refs: tuple(_ascii(ref) for ref in refs))
        )
    return tuple(output)
