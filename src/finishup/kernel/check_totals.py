"""Bounded structural totals for the exact work state a check examined.

These counts describe recorded work, not proof that its assertions are correct. In particular,
an attempted item is an action assertion and a linked evidence record may still be weak or stale.
No command, path, prose, or caller-defined key is copied into the totals.
"""

from __future__ import annotations

from typing import cast

from finishup.domain.check_totals import CHECK_TOTAL_KEYS, validate_check_totals
from finishup.domain.events import ActionKind, ObligationStatus, ResultOutcome
from finishup.domain.findings import Finding, finding_demands_work
from finishup.domain.values import EvidenceId, JsonObject, ObligationId
from finishup.kernel.claims import (
    claim_discloses_result,
    effective_claim_items,
    result_is_relevant_to_claim,
)
from finishup.kernel.command_attempts import attempted_items_for_obligation
from finishup.kernel.deterministic_checks import DeterministicCase
from finishup.kernel.observed_failures import (
    ObservedFailureState,
    observed_action_runner_class,
    observed_event_ids_from_coverage,
    observed_failure_exempt,
    observed_failure_states,
)
from finishup.kernel.outcome_corrections import superseded_unknown_results
from finishup.kernel.plan_scope import current_plan_scope
from finishup.kernel.test_edit_visibility import PreExistingTestEdits

__all__ = ["build_check_totals"]


def build_check_totals(
    case: DeterministicCase,
    findings: tuple[Finding, ...] = (),
    suppressed_count: int = 0,
    test_edits: PreExistingTestEdits | None = None,
) -> JsonObject:
    """Summarize the effective plan and observed commands at the frozen check frontier.

    Failed exploration remains in historical command counts. Only failures relevant to the
    effective plan contribute to ``live_failed``; a disclosed failure is still live, never green.
    Finding disposition counts remain in the existing finding checklist, whose post-check state
    is distinct from these frozen-work and returned-finding counts.
    """

    state = case.projection
    scope = current_plan_scope(state.plans, state.coverage_gaps)
    active: frozenset[ObligationId] = (
        frozenset(cast(tuple[ObligationId, ...], scope.effective_obligation_refs or ()))
        if scope.readable
        else frozenset[ObligationId]()
    )
    obligations = dict.fromkeys(CHECK_TOTAL_KEYS["obligations"], 0)
    requested = dict.fromkeys(CHECK_TOTAL_KEYS["requested_items"], 0)
    obligations["scope_known"] = int(scope.readable)
    obligations["declared"] = len(active)
    for obligation in active:
        record = state.obligations.get(obligation)
        payload = None if record is None else record.payload
        if payload is None:
            obligations["unreadable"] += 1
            continue
        if payload.status is ObligationStatus.RESOLVED:
            obligations["resolved"] += 1
        elif payload.status is not ObligationStatus.ACKNOWLEDGED_NOT_DONE:
            # #997: an acknowledged obligation is neither open nor resolved; the rendering
            # names the remainder of ``declared`` as acknowledged, so it is counted once.
            obligations["open"] += 1
        attempted = attempted_items_for_obligation(state, obligation)
        for item in payload.requested_items:
            requested["attempted" if item.value in attempted else "unattempted"] += 1
        evidence_refs: set[str] = set(payload.resolution_evidence_refs)
        for result in state.results.values():
            if result.payload is None:
                continue
            action = state.actions.get(result.payload.action_id)
            if (
                action is not None
                and action.payload is not None
                and obligation in action.payload.obligation_refs
            ):
                evidence_refs.update(result.payload.evidence_refs)
        for _, claim in effective_claim_items(state):
            if claim.payload is not None and obligation in claim.payload.obligation_refs:
                evidence_refs.update(claim.payload.supporting_refs)
        if any(
            str(ref).startswith("evd_")
            and (item := state.evidence.get(EvidenceId(str(ref)))) is not None
            and item.payload is not None
            for ref in evidence_refs
        ):
            obligations["with_evidence"] += 1

    observed = observed_event_ids_from_coverage(case.coverage_by_ref)
    failures = observed_failure_states(state, observed, through=case.frontier.sequence)
    commands = dict.fromkeys(CHECK_TOTAL_KEYS["commands"], 0)
    # One host call is one command: a Codex hook result recorded as unknown and later enriched
    # by the stream's corrected outcome for the same action counts once, with that outcome (#1001).
    superseded = superseded_unknown_results(state.results, include=observed.__contains__)
    for result_id, result in state.results.items():
        payload = result.payload
        if payload is None or result.source_event_id not in observed or result_id in superseded:
            continue
        action = state.actions.get(payload.action_id)
        if (
            action is None
            or action.payload is None
            or action.source_event_id not in observed
            or action.payload.action_kind is not ActionKind.COMMAND
        ):
            continue
        commands["observed"] += 1
        if payload.outcome is ResultOutcome.UNKNOWN:
            commands["unknown"] += 1
        if payload.outcome not in {ResultOutcome.FAILURE, ResultOutcome.PARTIAL}:
            continue
        commands["failed"] += 1
        failure_state = failures.get(result_id)
        if failure_state in {ObservedFailureState.SUPERSEDED, ObservedFailureState.RERUN}:
            commands["retired_by_rerun"] += 1
        relevant = not action.payload.obligation_refs or bool(
            active.intersection(action.payload.obligation_refs)
        )
        if (
            failure_state is not ObservedFailureState.LIVE
            or not relevant
            or observed_failure_exempt(action.payload, payload)
        ):
            continue
        commands["live_failed"] += 1
        if observed_action_runner_class(action.payload.description) == "test" and any(
            claim.payload is not None
            and claim_discloses_result(claim.payload, result_id)
            and result_is_relevant_to_claim(state, claim, result_id)
            for _, claim in effective_claim_items(state)
        ):
            commands["disclosed_not_rerun_green"] += 1

    evidence = dict.fromkeys(CHECK_TOTAL_KEYS["evidence"], 0)
    for ref, record in state.evidence.items():
        if ref in case.allowed_ids and record.payload is not None:
            evidence[record.payload.strength.value] += 1
    # ADR-046: a reviewer's limitation request asks for a disclosure, not work, so it counts as
    # coverage-only here exactly as it does everywhere else.
    actionable = sum(finding_demands_work(finding) for finding in findings)
    returned = {
        "returned": len(findings),
        "actionable_returned": actionable,
        "coverage_only_returned": len(findings) - actionable,
        "suppressed": suppressed_count,
    }
    test_edit_counts = {
        "examined": 0 if test_edits is None else 1,
        "baseline_known": 0 if test_edits is None else int(test_edits.baseline_known),
        "modified": 0 if test_edits is None else test_edits.modified,
        "renamed": 0 if test_edits is None else test_edits.renamed,
        "deleted": 0 if test_edits is None else test_edits.deleted,
        "skipped": 0 if test_edits is None else test_edits.skipped,
        "unjustified": 0 if test_edits is None else test_edits.unjustified,
        "unknown": 0 if test_edits is None else test_edits.unknown,
    }
    groups = {
        "obligations": obligations,
        "requested_items": requested,
        "commands": commands,
        "evidence": evidence,
        "findings": returned,
        "test_edits": test_edit_counts,
    }
    return validate_check_totals(
        {
            group: {key: str(value) for key, value in sorted(counts.items())}
            for group, counts in groups.items()
        }
    )
