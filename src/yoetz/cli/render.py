"""Bounded, non-strengthening human renderers for public CLI results."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from enum import Enum
from typing import Final, cast

from yoetz.domain.check_totals import render_check_totals
from yoetz.domain.findings import SELF_VERIFIED_GUIDANCE
from yoetz.domain.receipts import (
    SEMANTIC_REDACTED_VALUES_AGENT_LINE,
    check_time_change_gap_sentence,
    historical_gaps_from_wire,
    semantic_redacted_value_text,
)
from yoetz.domain.review_input_render import (
    has_agent_suppliable_missing,
    render_missing_for_assessment_lines,
    render_review_input_manifest_compat_line,
    render_review_input_manifest_lines,
)
from yoetz.kernel.fact_lineage import FactLineage, lineage_from_wire, lineage_texts
from yoetz.protocol.canonical import JsonValue
from yoetz.protocol.errors import normalize_safe_details
from yoetz.protocol.ids import validate_opaque_item_id
from yoetz.protocol.models import (
    CheckAwaitingHumanModel,
    CheckFindingChecklistModel,
    CheckOverallNextModel,
    CheckProjectedFindingModel,
    CheckSuccessModel,
    OmittedContentModel,
    PublicErrorModel,
    ReceiptSuccessModel,
    SemanticRedactedValueModel,
    StatusAdvicePageModel,
    StatusCheckAdmissionModel,
    StatusClosureReadinessModel,
    StatusCompactPageModel,
    StatusEvidencePageModel,
    StatusFindingsPageModel,
    StatusLineagePageModel,
    StatusObligationsPageModel,
    StatusOperationPageModel,
    StatusProjectPageModel,
    StatusResultsPageModel,
    StatusSemanticProgressModel,
    StatusSuccessModel,
)
from yoetz.protocol.readiness_text import (
    awaiting_ruling_variants,
    check_cause_sentence,
    closure_counts_variants,
    predicted_receipt_variants,
    readiness_directive,
    recheck_note,
)
from yoetz.protocol.recovery import (
    RecoveryDirective,
    TimeoutOperationKind,
    continuation_for_local_reason,
    continuation_for_reason,
    continuation_for_semantic_outcome,
    correction_for_invariant,
    directive_for,
)
from yoetz.protocol.redacted_values import SemanticRedactedValue

__all__ = [
    "bounded_failure_line",
    "ceremony_refusal_line",
    "error_recovery_json",
    "local_recovery_json",
    "recovery_directive_json",
    "credential_heuristic_line",
    "lineage_lines",
    "render_closure_readiness_lines",
    "render_error_recovery_lines",
    "render_hook_recovery_suffix",
    "render_human_awaiting_human",
    "render_human_check",
    "render_human_error",
    "render_human_findings",
    "render_human_receipt",
    "render_human_status",
    "render_local_recovery_lines",
    "render_recovery_directive_lines",
    "render_semantic_outcome_recovery_lines",
    "render_semantic_progress_lines",
]


def _token(value: object) -> str:
    if isinstance(value, Enum):
        return str(value.value)
    return str(value)


def _count(value: str | None) -> str:
    """Render an unknown readiness count as unknown, never as a bare ``None`` or a zero."""

    return "unavailable" if value is None else value


def _failure_class_from_provenance(provenance: object) -> object | None:
    if provenance is None:
        return None
    if isinstance(provenance, Mapping):
        return cast(Mapping[str, object], provenance).get("failure_class")
    return getattr(provenance, "failure_class", None)


def render_semantic_outcome_recovery_lines(
    *,
    status: object,
    reason: object,
    provenance: object = None,
) -> list[str]:
    """Resolve provider-review recovery from recorded status, never from findings."""

    token = continuation_for_semantic_outcome(
        status=status,
        reason=reason,
        failure_class=_failure_class_from_provenance(provenance),
    )
    directive = directive_for(token)
    if directive is None:
        return []
    return render_recovery_directive_lines(directive)


def _semantic_outcome_recovery_lines(
    *,
    status: object,
    reason: object,
    provenance: object = None,
) -> list[str]:
    return render_semantic_outcome_recovery_lines(
        status=status, reason=reason, provenance=provenance
    )


def render_hook_recovery_suffix(
    reason: object,
    *,
    operation_kind: TimeoutOperationKind | None = None,
) -> str:
    """Return the hook-budget suffix for a typed reason, or an empty string.

    Hook intake is bounded at 512 ASCII bytes. The suffix therefore carries the
    continuation token only; each host hook keeps its own framing, and the
    directive text is reconstructed from the same registry on CLI and MCP.

    Pass one exact reason whose registry meaning matches the hook's own advice. A hook
    context shared by several reasons, or a service ``PublicErrorCode`` that only shares a
    spelling with a CLI-local reason (``storage_unsafe``), must not borrow a token: its
    directive would contradict the hook text beside it (issue #739).
    """

    token = continuation_for_local_reason(reason)
    if token is None:
        token = continuation_for_reason(reason, operation_kind=operation_kind)
    if token is None:
        return ""
    return f" Continuation: {token}."


def _projected_text(value: str | OmittedContentModel | None) -> str:
    if value is None:
        return "none"
    if isinstance(value, OmittedContentModel):
        return f"[omitted: {_token(value.category)}; {value.reason}]"
    return value


def render_human_findings(
    findings: Sequence[CheckProjectedFindingModel] | Sequence[object],
) -> str:
    """Render at most the first three already-ordered findings."""

    if not findings:
        return "Findings: none"
    lines = ["Findings:"]
    for finding in findings[:3]:
        kind = _token(getattr(finding, "kind", "unknown"))
        priority = getattr(finding, "priority", "unknown")
        origin = _token(getattr(finding, "origin", "unknown"))
        summary = _projected_text(getattr(finding, "summary", None))
        lines.append(f"- P{priority} {kind} ({origin}): {summary}")
        detail = getattr(finding, "detail", None)
        if detail is not None:
            lines.append(f"  {_projected_text(detail)}")
    remaining = len(findings) - 3
    if remaining > 0:
        lines.append(f"Additional findings not shown: {remaining}")
    return "\n".join(lines)


_CHECKBOX: Final = {
    "open": "[ ]",
    "verified_resolved": "[x]",
    "acknowledged_not_done": "[~]",
    "rejection_accepted": "[-]",
    # Issue #984: final, disclosed, not resolved by Yoetz.
    "self_verified": "[s]",
    # Issue #1020: final, disclosed standing disagreement; not agent work.
    "disputed_after_rebuttal": "[d]",
}
_CHECKLIST_NEXT_TEXT: Final = {
    "work_open_findings": (
        "Repair the open findings (or answer the reviewer's questions), then check again."
    ),
    "decide_at_budget": (
        "An open finding reached the review-round budget: repair it with new evidence, then "
        "check. "
        + SELF_VERIFIED_GUIDANCE
        + " Respond acknowledged_not_done with a reason only if you truly will not or cannot "
        "do it. Checks are never throttled."
    ),
    "disclose_limitations": (
        "Disclose the named limitation requests: respond acknowledged with the reason if the "
        "requirement may be met but cannot be verified here; respond acknowledged_not_done only "
        "when you know it is not met. No repair is needed."
    ),
    "request_receipt": "No open findings remain on the list; request the receipt.",
    "request_ruling": (
        "You rejected finding(s) and the reviewer has not ruled yet: run check with "
        "final_review: true so the reviewer rules. Do not acknowledge a finding you dispute."
    ),
}


def render_checklist_line(
    index: int, finding_id: str, todo_state: str | None, rounds: str | None, budget: str | None
) -> str:
    """One to-do line: ``[ ] F-3 fnd_... open (2/5)`` (issue #905). Structural tokens only."""

    state = _token(todo_state) if todo_state is not None else "unknown"
    line = f"{_CHECKBOX.get(state, '[?]')} F-{index} {finding_id} {state}"
    if state == "open" and rounds is not None and budget is not None:
        line += f" ({rounds}/{budget})"
    return line


def _render_checklist(
    checklist: CheckFindingChecklistModel, *, input_action_required: bool = False
) -> list[str]:
    lines = [f"To-do list (review-round budget {checklist.attempt_budget}):"]
    for index, item in enumerate(checklist.items, start=1):
        lines.append(
            "- "
            + render_checklist_line(
                index,
                item.finding_id,
                item.todo_state,
                item.review_rounds,
                checklist.attempt_budget,
            )
        )
    counts = checklist.counts
    at_budget = int(counts.open_at_budget)
    if counts.to_do is not None and counts.awaiting_ruling is not None:
        # ADR-046: the same finding counters status prints.
        sentence = closure_counts_variants(
            {
                "to_do": counts.to_do,
                "awaiting_ruling": counts.awaiting_ruling,
                "unmet": counts.unmet,
                "disclosed": counts.disclosed,
                "to_disclose": counts.to_disclose,
                "self_verify_eligible": "0",
            },
            None,
        )
        lines.extend(sentence[:1])
    lines.append(
        f"Counts: open {counts.open}"
        + (f" ({at_budget} at budget)" if at_budget else "")
        + f", verified {counts.verified_resolved}, not done {counts.acknowledged_not_done}, "
        f"rejection accepted {counts.rejection_accepted}"
        + (f", self-verified {counts.self_verified}" if int(counts.self_verified) else "")
        + (
            f", disputed after rebuttal {counts.disputed_after_rebuttal}"
            if counts.disputed_after_rebuttal is not None and int(counts.disputed_after_rebuttal)
            else ""
        )
    )
    total = sum(
        int(value)
        for value in (
            counts.open,
            counts.verified_resolved,
            counts.acknowledged_not_done,
            counts.rejection_accepted,
            counts.self_verified,
            counts.disputed_after_rebuttal or "0",
        )
    )
    if total > len(checklist.items):
        lines.append(f"Not listed: {total - len(checklist.items)}")
    label = "Finding checklist next" if input_action_required else "Next"
    next_text = _CHECKLIST_NEXT_TEXT[checklist.next]
    if checklist.next == "work_open_findings":
        next_text = _open_findings_next_text(checklist, next_text)
    lines.append(f"{label}: {next_text}")
    return lines


# tb4n3 RC-1 (ADR-046, owner decisions Q4 and 2026-10-12): a reviewer's limitation request is a
# disclosure to make, never repair work. Alone it is the ``disclose_limitations`` continuation;
# beside real work it rides in ``work_open_findings`` and the text names how it is answered. The
# agent's answer decides what it means: ``acknowledged`` says the requirement may be met but
# cannot be verified here, ``acknowledged_not_done`` says it is not met.
_LIMITATION_REQUEST_ALSO: Final = (
    " For a reviewer's request to state a limit, respond acknowledged with the reason if the "
    "requirement may be met but cannot be verified here (acknowledged_not_done only when you "
    "know it is not met) instead of repairing it."
)


def _open_limitation_requests(checklist: CheckFindingChecklistModel | None) -> bool:
    """Whether some open (agent work) checklist item is a limitation request still to disclose."""

    if checklist is None:
        return False
    # ADR-046: agent work is the closure class, not the to-do state (a disclosed limitation keeps
    # an ``open`` to-do state but is settled).
    return any(
        item.closure_class == "agent_work" and item.closure_basis == "limitation_requested"
        for item in checklist.items
    )


def _open_findings_next_text(checklist: CheckFindingChecklistModel, default: str) -> str:
    return default + _LIMITATION_REQUEST_ALSO if _open_limitation_requests(checklist) else default


def _render_overall_next(
    next_step: CheckOverallNextModel, checklist: CheckFindingChecklistModel | None = None
) -> str:
    if next_step.action == "supply_missing_input":
        action = (
            "Supply the named review input as new records tied to the named refs "
            "(never change your work to fit the reviewer)"
        )
    elif next_step.action == "disclose_limitations":
        action = (
            "Disclose the named limitation requests (respond acknowledged with the reason if the "
            "requirement may be met but cannot be verified here; acknowledged_not_done only when "
            "you know it is not met; no repair is needed)"
        )
    elif next_step.action == "work_open_findings":
        if _open_limitation_requests(checklist):
            action = (
                "Repair or answer the named open findings (a limitation request among them needs "
                "only a response: acknowledged with the reason if it may be met but cannot be "
                "verified here, acknowledged_not_done only when you know it is not met)"
            )
        else:
            action = "Repair or answer the named open findings"
    elif next_step.action == "request_ruling":
        action = "Run check with final_review: true so the reviewer rules on the rejected findings"
    elif next_step.action == "review_recorded_work":
        action = "Review the recorded work for open obligations or undisclosed failures"
    else:
        action = (
            "Disclose the limitation at the receipt endpoint"
            if next_step.status == "ready_with_limitations"
            else "Request the receipt"
        )
    targets = ""
    if next_step.target_refs:
        targets = " (targets: " + ", ".join(next_step.target_refs) + ")"
    endpoint = ""
    if next_step.acknowledged_incomplete_endpoint is not None:
        endpoint = "; acknowledged incomplete endpoint: receipt"
    predicted = ""
    if next_step.predicted_conclusion is not None:
        sentence = predicted_receipt_variants(
            {"conclusion": next_step.predicted_conclusion, "reasons": ()},
            state="action_required" if next_step.status == "action_required" else "ready",
        )
        predicted = f" {sentence[-1]}" if sentence else ""
    return f"Overall next [{next_step.status}]: {action}{targets}{endpoint}.{predicted}"


def render_human_check(result: CheckSuccessModel) -> str:
    """Render an exact check verdict and bounded AI-powered review status."""

    if type(result) is not CheckSuccessModel:
        raise TypeError("check_result_invalid")
    scoped_local_verdict = (
        result.verdict == "no_issue_detected"
        and result.semantic_status == "not_requested"
        and result.semantic_reason == "deterministic_mode"
    )
    verdict_line = (
        "Verdict: no issue detected within deterministic coverage"
        if scoped_local_verdict
        else f"Verdict: {result.verdict}"
    )
    review_line = (
        f"AI-powered review: {_token(result.semantic_status)} ({_token(result.semantic_reason)})"
    )
    if result.semantic_status == "not_requested" and result.semantic_route_required is False:
        # Issue #986 (owner decision E2): disclosed, never a receipt blocker on such a route.
        review_line += "; the route did not require it, so it does not block a clean receipt"
    lines = [
        verdict_line,
        review_line,
        render_human_findings(result.findings),
    ]
    if result.totals is not None:
        lines.insert(2, render_check_totals(result.totals.model_dump(mode="json")))
    if result.observations_awaited is not None:
        # Issue #1012: the optional pre-check wait for this task's hook rows.
        awaited = result.observations_awaited
        lines.insert(
            2,
            "Hook observations awaited: complete"
            if awaited.state == "complete"
            else (
                f"Hook observations awaited: bounded_timeout ({int(awaited.pending_count)} "
                "still pending; the check used the record as it stood)"
                if awaited.state == "bounded_timeout"
                else "Hook observations awaited: unavailable (local outbox not readable)"
            ),
        )
    if result.review_input_manifest is not None:
        compat_line = render_review_input_manifest_compat_line(
            result.review_input_manifest.model_dump(mode="json", by_alias=True)
        )
        if compat_line:
            lines.append(compat_line)
        lines.extend(
            render_review_input_manifest_lines(
                result.review_input_manifest.model_dump(mode="json", by_alias=True)
            )
        )
    recovery = _semantic_outcome_recovery_lines(
        status=result.semantic_status,
        reason=result.semantic_reason,
        provenance=result.semantic_provenance,
    )
    if recovery:
        lines.extend(recovery)
    suppressed = int(result.suppressed_count)
    if suppressed:
        lines.append(f"Suppressed findings: {suppressed}")
    if result.overall_next is not None:
        lines.append(_render_overall_next(result.overall_next, result.finding_checklist))
    if result.finding_checklist is not None:
        lines.extend(
            _render_checklist(
                result.finding_checklist,
                input_action_required=has_agent_suppliable_missing(result.missing_for_assessment),
            )
        )
    if result.children is not None:
        children = result.children
        lines.append(f"Child dependencies ({children.label}):")
        if children.tested_manifest_frontier is not None:
            lines.append(
                "Tested manifest frontier: "
                f"{children.tested_manifest_frontier.sequence} "
                f"({children.tested_manifest_frontier.head_digest})"
            )
        if children.label == "preview":
            lines.append("Preview facts do not change the recorded check.")
        for child in children.items:
            lines.append(
                f"- {child.child_task_id}: {_token(child.origin)}, {_token(child.acceptance)}; "
                f"work {_token(child.work_state)}, session {_token(child.session_health)}; "
                f"rollup {_token(child.rollup_state)}"
            )
            if child.blocking_conditions:
                lines.append("  Completion gaps: " + ", ".join(child.blocking_conditions))
    if result.advisory_notes:
        lines.append("Project advice (does not affect the verdict):")
        for note in result.advisory_notes:
            lines.append(
                f"- {note.kind}: {note.count}; project {note.project_id}; "
                "tasks " + ", ".join(note.task_ids)
            )
    if result.missing_for_assessment:
        # Issue #907: a check limitation, never a finding. Recheck only after supplying an
        # agent-suppliable item; otherwise report the limitation.
        lines.extend(render_missing_for_assessment_lines(result.missing_for_assessment))
    if result.semantic_withheld_items:
        lines.append("Withheld review items (the reviewer continued without them):")
        for item in result.semantic_withheld_items:
            lines.append(f"- {item.item_id}: {_token(item.reason)}")
    lines.extend(_semantic_redacted_value_lines(result.semantic_redacted_values))
    if "semantic_review_skipped_insufficient_packet" in tuple(result.coverage.known_gaps):
        lines.append(
            "AI-powered review skipped: the reviewer twice in a row (or four times since the last "
            "assessed review) "
            "could not assess the packet. This is a Yoetz limit, not a blocker: verify the work "
            "yourself; a real repair re-arms the review until that cap."
        )
    if result.coverage.known_gaps:
        lines.append("Coverage gaps: " + ", ".join(result.coverage.known_gaps))
        lines.extend(_check_time_change_sentences(result.coverage.known_gaps))
        lines.extend(lineage_lines(result.fact_lineage))
        # The strict ceiling blocked this process while the last install applied the policy
        # route (issue #537). A ceiling with no applied-policy record keeps today's terminal
        # wording with no recovery line.
        if "optional_semantic_review_registration_drift" in tuple(result.coverage.known_gaps):
            lines.append(
                "The last install applied the policy route. If this strict route was not "
                "intended, re-run `yoetz integrate codex mcp preview` and "
                "`yoetz integrate codex mcp install --route-profile policy`, then start "
                "a fresh Codex process."
            )
    return "\n".join(lines)


def render_semantic_progress_lines(progress: StatusSemanticProgressModel) -> tuple[str, ...]:
    """Render structural AI-powered review progress exactly as the JSON page states it.

    Only closed phase, outcome, and reason tokens plus service timestamps and derived whole
    seconds appear. Progress is a service observation, not evidence that the review is correct.
    """

    if type(progress) is not StatusSemanticProgressModel:
        raise TypeError("status_semantic_progress_invalid")
    elapsed = int(progress.elapsed_ms) // 1000
    lines = [
        f"Semantic review phase: {_token(progress.phase)} "
        f"(attempt {progress.attempt_ordinal}, {progress.condition})"
    ]
    if progress.condition == "terminal":
        lines.append(
            f"Semantic review outcome: {progress.terminal_outcome} "
            f"({_token(progress.terminal_reason)}); elapsed {elapsed}s"
        )
        return tuple(lines)
    remaining = int(progress.remaining_ms or "0") // 1000
    lines.append(
        f"Semantic review elapsed: {elapsed}s; remaining {remaining}s; "
        f"deadline {progress.deadline_at}"
    )
    if progress.condition == "overdue":
        lines.append(
            "Semantic review deadline passed without a terminal record. Retry the same "
            "request_id to recover the terminal result."
        )
    return tuple(lines)


def render_check_admission_lines(admission: StatusCheckAdmissionModel) -> tuple[str, ...]:
    """Render why a check request id has no operation yet, exactly as the JSON page states it.

    Only the closed stage token, a count, and whole seconds derived by the service appear. The
    stage is a transient service observation, not a verdict about the work (issue #838).
    """

    if type(admission) is not StatusCheckAdmissionModel:
        raise TypeError("status_check_admission_invalid")
    elapsed = int(admission.elapsed_ms) // 1000
    return (
        f"Check admission: {_token(admission.stage)} "
        f"(refusals {admission.refusal_count}); elapsed {elapsed}s",
        "Nothing is recorded under this request ID yet. Wait "
        f"{admission.retry_after_ms} ms, then replay the exact same check request.",
    )


def render_closure_readiness_lines(readiness: StatusClosureReadinessModel) -> tuple[str, ...]:
    """Render the closure checklist: its state, the frozen directive, and each named group.

    Shared by the CLI and the terminal interface. Only the closed state token, service counts,
    classified gap or condition tokens and service-minted item ids appear (issue #913). An
    acknowledged item is listed as not done; it is never rendered as resolved.
    """

    if type(readiness) is not StatusClosureReadinessModel:
        raise TypeError("status_closure_readiness_invalid")
    if (
        readiness.state is None
        or readiness.agent_actionable is None
        or readiness.standing_limitations is None
        or readiness.acknowledged_not_done is None
        or readiness.acknowledged_not_done_count is None
    ):
        return ()  # A result shaped by an earlier build carries no checklist.
    lines = [
        f"Closure: {readiness.state}",
        readiness_directive(
            readiness.state,
            standing=len(readiness.standing_limitations),
            acknowledged=readiness.acknowledged_not_done_count,
        ),
    ]
    if readiness.state != "unknown":
        # ADR-046: the receipt conclusion this frontier would carry, appended after the
        # owner-approved sentence, and the one set of counters every surface prints.
        lines.extend(
            predicted_receipt_variants(readiness.predicted_receipt, state=readiness.state)[:1]
            if readiness.predicted_receipt is not None
            else ()
        )
        lines.extend(
            closure_counts_variants(readiness.finding_counts, readiness.obligation_counts)[:1]
        )
        # The rejected findings that wait for a reviewer ruling and the re-reads a Stop will ask
        # once (tb4n3 RC-8), so "nothing further to do" is never followed by a surprise gate.
        lines.extend(awaiting_ruling_variants(readiness)[:1])
        announced = recheck_note(readiness)
        if announced is not None:
            lines.append(announced)
    if readiness.agent_actionable and readiness.state != "unknown":
        lines.append("Agent-actionable: " + ", ".join(readiness.agent_actionable))
    if readiness.check_cause is not None and readiness.state != "unknown":
        # tb4n3 RC-6 (owner lineage rule): the record the check's standing rests on.
        cause = readiness.check_cause
        lines.append(
            check_cause_sentence(
                effect=cause.effect,
                event_id=cause.event_id,
                ledger_sequence=cause.ledger_sequence,
                check_subject_frontier=cause.check_subject_frontier,
                family=cause.family,
                material_class=cause.material_class,
                rule=cause.rule,
                tool=cause.tool,
            )
        )
    if readiness.standing_limitations:
        lines.append("Standing limitations: " + ", ".join(readiness.standing_limitations))
    lines.extend(lineage_lines(readiness.fact_lineage))
    if readiness.blocked_obligations:
        # Recorded yoetz-blocker claims (#977): ids and the closed kind; Yoetz did not verify them.
        lines.append(
            "Recorded blockers (agent-declared, unverified): "
            + ", ".join(
                f"{item.obligation_id} ({item.blocker_kind})"
                for item in readiness.blocked_obligations
            )
        )
    if readiness.limitation_refs_required and readiness.limitation_refs_required_count:
        # F3: ids only; what a whole-task completion claim must name in limitation_refs.
        hidden = int(readiness.limitation_refs_required_count) - len(
            readiness.limitation_refs_required
        )
        lines.append(
            "A whole-task completion claim must name in limitation_refs: "
            + ", ".join(readiness.limitation_refs_required)
            + (f" (+{hidden} more)" if hidden > 0 else "")
        )
    if readiness.acknowledged_not_done:
        listed = ", ".join(readiness.acknowledged_not_done)
        hidden = int(readiness.acknowledged_not_done_count) - len(readiness.acknowledged_not_done)
        lines.append(
            "Acknowledged, not done: " + listed + (f" (+{hidden} more)" if hidden > 0 else "")
        )
    return tuple(lines)


_FILTER_WORDS: Final = {"enforced": "on", "disabled": "off", "unknown": "unknown"}


def credential_heuristic_line(repository: object, machine_default: object) -> str:
    """One sentence for the external reviewer's possible-credential filter (issue #982).

    Every human surface (``yoetz status``, provider status, the terminal interface) uses this
    text for the same ``repository``/``machine_default`` pair, so they cannot disagree, and each
    names the command that changes what it reports.
    """

    repo = repository if type(repository) is str and repository in _FILTER_WORDS else "unknown"
    default = (
        machine_default
        if type(machine_default) is str and machine_default in _FILTER_WORDS
        else "unknown"
    )
    line = (
        "Possible-credential filter (external reviewer): "
        f"{_FILTER_WORDS[repo]} for this repository; installation default {_FILTER_WORDS[default]}"
    )
    if repo == "disabled":
        line += ". Turn it back on here with 'yoetz privacy credential-heuristic enable'"
    if default == "disabled":
        line += (
            ". New repository grants start with it off; restore the default with "
            "'yoetz privacy credential-heuristic enable --machine-default'"
        )
    return line


def _credential_heuristic_lines(result: StatusSuccessModel) -> tuple[str, ...]:
    """The possible-credential filter for the external reviewer (issue #982)."""

    state = result.credential_heuristic
    if state is None:
        return ()
    return (credential_heuristic_line(state.repository, state.machine_default),)


def render_human_status(result: StatusSuccessModel) -> str:
    """Render current structural status without dumping the ledger."""

    if type(result) is not StatusSuccessModel:
        raise TypeError("status_result_invalid")
    lines = [
        f"Frontier: {result.head_frontier.sequence}",
        f"Freshness: {_token(result.coverage.ledger_freshness)}",
        f"Open obligations: {_count(result.closure_readiness.open_obligation_count)}",
        *(
            # #997: counted apart, never in the open count.
            (
                "Obligations acknowledged as not done: "
                f"{_count(result.closure_readiness.acknowledged_obligation_count)}",
            )
            if result.closure_readiness.acknowledged_obligation_count not in {None, "0"}
            else ()
        ),
        f"Unanswered findings: {_count(result.closure_readiness.unanswered_finding_count)}",
        *render_closure_readiness_lines(result.closure_readiness),
        *_credential_heuristic_lines(result),
    ]
    if isinstance(result.page, StatusCompactPageModel):
        for item in result.page.items:
            latest_check = item.latest_check
            if latest_check is not None:
                lines.append(
                    f"Latest check: {latest_check.verdict}; checked frontier "
                    f"{latest_check.checked_frontier.sequence}; event {latest_check.check_event_id}"
                )
            edits = item.latest_check_test_edits
            if edits is not None:
                lines.append(
                    "Latest check test edits: "
                    f"{edits.read_availability}; checked frontier {edits.checked_frontier.sequence}; "
                    f"{edits.modified} modified, {edits.renamed} renamed, "
                    f"{edits.deleted} deleted, {edits.skipped} skipped, "
                    f"{edits.unjustified} unjustified, {edits.unknown} unknown "
                    f"(baseline known {edits.baseline_known})"
                )
    if isinstance(result.page, StatusOperationPageModel):
        lines.extend((f"Operation: {result.page.operation_request_id} ({result.page.state})",))
        if result.page.continuation is not None:
            lines.extend(
                (
                    f"Continuation: {result.page.continuation.kind}",
                    "Trusted command: " + " ".join(result.page.continuation.command),
                    f"Replay request ID: {result.page.continuation.replay_request_id}",
                )
            )
        if result.page.semantic_progress is not None:
            lines.extend(render_semantic_progress_lines(result.page.semantic_progress))
        if result.page.semantic_withheld_items:
            lines.append("Withheld review items (the reviewer continued without them):")
            lines.extend(
                f"- {item.item_id}: {_token(item.reason)}"
                for item in result.page.semantic_withheld_items
            )
        lines.extend(_semantic_redacted_value_lines(result.page.semantic_redacted_values or ()))
        if result.page.admission is not None:
            lines.extend(render_check_admission_lines(result.page.admission))
    elif isinstance(result.page, StatusLineagePageModel):
        lines.extend(_render_lineage(result.page))
    elif isinstance(result.page, StatusAdvicePageModel):
        lines.append("Advice:")
        for item in result.page.items:
            if item.coordination_detection_id is not None:
                lines.append(
                    f"- Coordination overlap {item.coordination_detection_id}: "
                    f"counterpart {item.coordination_counterpart_task_id}; "
                    f"project {item.coordination_project_id}"
                )
                paths = item.coordination_resource_paths
                if paths is not None:
                    if isinstance(paths, OmittedContentModel):
                        lines.append("  Resources: " + _projected_text(paths))
                    else:
                        lines.append("  Resources: " + ", ".join(paths))
            else:
                lines.append(
                    f"- {item.rule_code}: priority {item.priority}; "
                    f"next {item.recommended_next_action}"
                )
        if result.page.next_cursor is not None:
            lines.append(f"Next page: {result.page.next_cursor}")
    elif isinstance(result.page, StatusProjectPageModel):
        page = result.page
        lines.extend(
            (
                f"Project: {page.project_id} ({_token(page.kind)})",
                f"Membership generation: {page.membership_generation}",
                f"Coordination grant: {_token(page.grant_state)}",
                "Members:",
            )
        )
        if page.title is not None:
            lines.insert(len(lines) - 1, "Title: " + _projected_text(page.title))
        if page.description is not None:
            lines.insert(len(lines) - 1, "Description: " + _projected_text(page.description))
        for member in page.members:
            lines.append(
                f"- {member.task_id}: {_token(member.work_state)}, "
                f"session {_token(member.session_health)} ({member.actor_id or 'unknown actor'})"
            )
        lines.extend(_render_lineage(page.lineage))
        lines.append("Coordination detections:")
        for detection in page.detections:
            lines.append(
                f"- {detection.detection_id}: {detection.resource_count} resources; "
                f"{'open' if detection.open else 'addressed'}"
            )
            if detection.resource_paths is not None:
                if isinstance(detection.resource_paths, OmittedContentModel):
                    lines.append("  Resources: " + _projected_text(detection.resource_paths))
                else:
                    lines.append("  Resources: " + ", ".join(detection.resource_paths))
        lines.append("Coordination coverage:")
        for coverage in page.coverage:
            lines.append(f"- {coverage.task_id}: {coverage.coverage} ({coverage.gap_code})")
        lines.append("Member receipts:")
        for receipt in page.receipts:
            lines.append(f"- {receipt.task_id}: {receipt.conclusion} ({receipt.receipt_id})")
        if page.next_cursor is not None:
            lines.append(f"Next page: {page.next_cursor}")
    if isinstance(result.page, StatusEvidencePageModel):
        # One line per row: the ledger-recorded channel lets a reader tell cooperative evidence
        # from host-observed captures without reading any prose.
        for item in result.page.items:
            availability = "" if item.available else ", unavailable"
            # Rows from earlier 0.3 builds carry no channel; omit the segment rather than guess.
            channel = "" if item.publication_channel is None else f" {item.publication_channel}"
            lines.append(
                f"{item.evidence_id}{channel} {item.strength}"
                f"{availability}: {_projected_text(item.description)}"
            )
        if result.page.next_cursor is not None:
            lines.append(f"Next page: {result.page.next_cursor}")
    if isinstance(result.page, StatusFindingsPageModel):
        for index, finding in enumerate(result.page.items, start=1):
            if finding.todo_state is not None:
                lines.append(
                    render_checklist_line(
                        index,
                        finding.finding_id,
                        finding.todo_state,
                        finding.review_rounds,
                        result.page.attempt_budget,
                    )
                )
            lines.append(
                f"{finding.finding_id} resolved={finding.resolved}: "
                + _projected_text(finding.detail)
            )
            if finding.finding_frontier is not None:
                # The frontier respond accepts as finding_frontier, as-is (#917).
                lines.append(
                    f"  finding_frontier: {finding.finding_frontier.sequence} "
                    f"({finding.finding_frontier.head_digest})"
                )
            if finding.duplicate_of_finding_id is not None:
                # Issue #996: the to-do state above is the earlier finding's while this holds.
                lines.append(f"  duplicate of: {finding.duplicate_of_finding_id}")
    if isinstance(result.page, StatusResultsPageModel):
        lines.extend(_render_result_items(result.page))
    if isinstance(result.page, StatusObligationsPageModel):
        for obligation in result.page.items:
            for attempt in obligation.command_attempts[:3]:
                lines.append(
                    f"{obligation.obligation_id} command item {attempt.requested_item_index}: {attempt.relation} (attempt only, not success)"
                )
            remaining = len(obligation.command_attempts) - 3
            if remaining > 0:
                lines.append(
                    f"{obligation.obligation_id}: {remaining} more command attempts; use JSON status for all items"
                )
    gaps = tuple(result.gaps) + tuple(result.coverage.known_gaps)
    lines.append("Gaps: " + (", ".join(dict.fromkeys(gaps)) if gaps else "none"))
    lines.extend(_check_time_change_sentences(tuple(dict.fromkeys(gaps))))
    return "\n".join(lines)


def _render_result_items(page: StatusResultsPageModel) -> list[str]:
    """One structural line per result; observed runs name tool, order, identity and exit (#909)."""

    lines = ["Results:"]
    if not page.items:
        lines.append("- none in this page")
    for item in page.items:
        line = f"- {item.result_id}: {_token(item.outcome) if item.outcome else 'unavailable'}"
        run = item.observed_run
        if run is not None:
            details = [f"observed run {run.occurrence}"]
            if run.tool_name is not None:
                details.append(f"tool {run.tool_name}")
            if run.exit_status is not None:
                details.append(f"exit {run.exit_status}")
            if run.command_commitment is not None:
                details.append(f"command {run.command_commitment}")
            line += " (" + "; ".join(details) + ")"
        lines.append(line)
    if page.next_cursor is not None:
        lines.append(f"Next page: {page.next_cursor}")
    return lines


_MAX_LINEAGE_LINES: Final = 6


def lineage_lines(lineage: Iterable[object] | None) -> list[str]:
    """One ``Why:`` sentence per derived fact's provenance (ADR-045); the same text everywhere.

    ``lineage`` holds ``FactLineageModel`` rows (status, check result); a row that does not parse
    is skipped, never guessed. At most ``_MAX_LINEAGE_LINES`` are shown, the rest counted.
    """

    items: list[FactLineage] = []
    for entry in lineage or ():
        try:
            items.append(lineage_from_wire(entry))
        except TypeError, ValueError:
            continue
    texts = lineage_texts(items)
    lines = list(texts[:_MAX_LINEAGE_LINES])
    if len(texts) > _MAX_LINEAGE_LINES:
        lines.append(
            f"(+{len(texts) - _MAX_LINEAGE_LINES} more facts with provenance in JSON status)"
        )
    return lines


def _check_time_change_sentences(codes: Iterable[str]) -> list[str]:
    """The fixed sentence for each check-time change unavailability code (ADR-031)."""

    return [
        sentence for code in codes if (sentence := check_time_change_gap_sentence(code)) is not None
    ]


def _render_lineage(page: StatusLineagePageModel) -> list[str]:
    lines = [f"Parent task: {page.parent_task_id or 'none'}", "Child tasks:"]
    if not page.children:
        lines.append("- none in this page")
    for child in page.children:
        lines.append(
            f"- {child.task_id}: {_token(child.origin)}, {_token(child.acceptance)}; "
            f"work {_token(child.work_state)}, session {_token(child.session_health)}; "
            f"rollup {_token(child.rollup_state)}"
        )
        if child.blocking_conditions:
            lines.append("  Completion gaps: " + ", ".join(child.blocking_conditions))
    for annotation in page.annotations:
        lines.append(f"- Observed subagent {annotation.correlation_id}: pending child binding")
    if page.next_cursor is not None:
        lines.append(f"Next page: {page.next_cursor}")
    return lines


def render_human_receipt(result: ReceiptSuccessModel) -> str:
    """Render the receipt conclusion without claiming stronger assurance."""

    if type(result) is not ReceiptSuccessModel:
        raise TypeError("receipt_result_invalid")
    lines = [f"Conclusion: {result.conclusion}"]
    if result.human_text is not None:
        lines.append(_projected_text(result.human_text))
    # The result's coverage names live gaps only (issue #1017); a JSON receipt also lists the
    # gaps a later check cleared, apart, and markdown/text carry them in ``human_text``.
    limitations = tuple(result.coverage.known_gaps)
    lines.append("Limitations: " + (", ".join(limitations) if limitations else "none declared"))
    document = result.document
    if isinstance(document, Mapping):
        historical = historical_gaps_from_wire(document)
        if historical:
            lines.append(
                "Cleared earlier (historical, not a current limitation): "
                + ", ".join(f"{code} (cleared at frontier {seq})" for code, seq in historical)
            )
        withheld = _semantic_withheld_item_lines(document)
        if withheld:
            lines.extend(withheld)
        raw_redacted = document.get("semantic_redacted_values")
        if isinstance(raw_redacted, (list, tuple)):
            lines.extend(_semantic_redacted_value_lines(cast(Sequence[object], raw_redacted)))
        provenance = document.get("semantic_provenance")
        if isinstance(provenance, Mapping):
            lines.extend(
                render_semantic_outcome_recovery_lines(
                    status=provenance.get("status"),
                    reason=provenance.get("reason"),
                    provenance=provenance,
                )
            )
    if result.suppressed_finding_count:
        lines.append(f"Suppressed findings: {result.suppressed_finding_count}")
    return "\n".join(lines)


def _semantic_redacted_value_lines(items: Sequence[object]) -> list[str]:
    """PL2-1: item refs and line numbers, then the fixed agent line once; never a value."""

    values: list[SemanticRedactedValue] = []
    for item in items:
        try:
            if isinstance(item, SemanticRedactedValueModel):
                values.append(
                    SemanticRedactedValue(
                        item.item_id, item.disposition, tuple(item.lines), item.source_ref
                    )
                )
            else:
                values.append(SemanticRedactedValue.from_wire(item))
        except TypeError, ValueError:
            continue
    if not values:
        return []
    return [
        "Withheld from external review (refs and lines only; no value is shown):",
        *(f"- {semantic_redacted_value_text(value)}" for value in values),
        SEMANTIC_REDACTED_VALUES_AGENT_LINE,
    ]


def _semantic_withheld_item_lines(document: Mapping[str, JsonValue]) -> list[str]:
    """Render only the closed opaque identity and reason from a receipt document."""

    raw_items = document.get("semantic_withheld_items")
    if not isinstance(raw_items, (list, tuple)):
        return []
    items: list[tuple[str, str]] = []
    for raw in raw_items:
        if not isinstance(raw, Mapping):
            continue
        item_id = raw.get("item_id")
        reason = raw.get("reason")
        if type(reason) is not str or reason != "never_send_heuristic":
            continue
        try:
            validate_opaque_item_id(item_id)
        except TypeError, ValueError:
            continue
        items.append((cast(str, item_id), reason))
    if not items:
        return []
    return [
        "Withheld review items (the reviewer continued without them):",
        *(f"- {item_id}: {reason}" for item_id, reason in items),
    ]


def render_recovery_directive_lines(
    directive: RecoveryDirective, *, commands: Sequence[str] = ()
) -> list[str]:
    """Render one frozen directive the way every CLI error surface shows it.

    The CLI has no text ceiling, so unlike the MCP text projection it renders the whole
    directive, any carried commands, its guidance pointer, and its nudge on separate lines.
    """

    lines = [f"Continuation: {directive.token}", f"Next: {directive.directive}"]
    if commands:
        lines.append("Commands: " + "; ".join(commands))
    if directive.guidance_uri is not None:
        lines.append(f"Guidance: {directive.guidance_uri}")
    if directive.nudge is not None:
        lines.append(directive.nudge)
    return lines


def render_local_recovery_lines(reason: object) -> list[str]:
    """Return the directive lines for a CLI lifecycle, instance, or ceremony reason, or [].

    These reasons never become a public error envelope: the CLI prints a bounded token line and
    exits. Before ADR-030 the line carried a remediation sentence and nothing else, so the same
    condition that gets a typed directive over MCP got none here. The lookup is the local-reason
    vocabulary only; a protocol reason code deliberately resolves to nothing through it.
    """

    directive = directive_for(continuation_for_local_reason(reason))
    if directive is None:
        return []
    return render_recovery_directive_lines(directive)


def bounded_failure_line(reason: str, *, prefix: str | None = None) -> str:
    """Render one bounded local reason with its remediation and its recovery directive.

    The single shape every human-rendered CLI refusal uses (issue #741): the bounded token stays
    first so machine-readable expectations hold, the per-reason remediation follows it on the same
    line, and the registry directive follows on its own lines. A reason with neither is returned
    unchanged, so a caller can tell "nothing is known about this token" from the result.
    """

    from yoetz.cli.exits import remediation_message

    head = reason if prefix is None else f"{prefix}: {reason}"
    remediation = remediation_message(reason)
    line = head if remediation is None else f"{head}: {remediation}"
    return "\n".join([line, *render_local_recovery_lines(reason)])


def ceremony_refusal_line(reason: str) -> str | None:
    """Render a structural ceremony refusal with its directive, or None when unmapped.

    A declined confidential ceremony already carries its own operator-facing sentence, token
    first. Only the directive lines are added, so the refusal reads the same way it did while
    gaining the continuation an agent needs to stop rather than restart a healthy service.
    """

    from yoetz.cli.exits import ceremony_refusal_message

    message = ceremony_refusal_message(reason)
    if message is None:
        return None
    return "\n".join([message, *render_local_recovery_lines(reason)])


def _resolve_error_recovery(
    safe_details: object,
) -> tuple[tuple[str, str] | None, RecoveryDirective | None, list[str]]:
    """Resolve the recovery facts of a public error from its gated safe details only.

    Returns the claim-revision invariant and correction, the continuation directive, and the
    carried frozen commands. Nothing is read from the error message, and a token the protocol
    normalizer does not admit resolves to nothing. The human and JSON renderings both read this,
    so they cannot disagree about what an error says to do.
    """

    if not isinstance(safe_details, Mapping):
        return None, None, []
    source = cast(Mapping[str, object], safe_details)
    # A claim-revision rejection carries its correction on the invariant rather than a
    # continuation token. The CLI rendered nothing for it before ADR-030 moved the corrective
    # phrases into the shared registry, so the same rejection read as bare prose here while the
    # MCP text channel explained it.
    revision_pair: tuple[str, str] | None = None
    revision = normalize_safe_details(
        {"invariant": source.get("invariant"), "reason_code": source.get("reason_code")}
    )
    if revision.get("reason_code") == "claim_revision_mismatch":
        correction = correction_for_invariant(revision.get("invariant"))
        if correction is not None:
            revision_pair = (str(revision["invariant"]), correction)
    gated = normalize_safe_details({"continuation": source.get("continuation")})
    directive = directive_for(gated.get("continuation"))
    if directive is None:
        return revision_pair, None, []
    gated_commands = normalize_safe_details(
        {key: source.get(key) for key in ("prepare_command", "review_command", "authorize_command")}
    )
    commands = [
        str(gated_commands[key])
        for key in ("prepare_command", "review_command", "authorize_command")
        if type(gated_commands.get(key)) is str
    ]
    return revision_pair, directive, commands


def render_error_recovery_lines(safe_details: object) -> list[str]:
    """Return the frozen recovery directive lines for a typed continuation, or an empty list.

    The directive is reconstructed locally from the continuation token (issue #739); nothing is
    read from the error message, and no line is rendered for a token the protocol normalizer does
    not admit. The CLI has no text ceiling, so unlike the MCP text projection it renders the
    whole directive, its guidance pointer, and its nudge on separate lines.
    """

    revision, directive, commands = _resolve_error_recovery(safe_details)
    lines: list[str] = []
    if revision is not None:
        lines.append(f"Invariant: {revision[0]}")
        lines.append(f"Correction: {revision[1]}")
    if directive is not None:
        lines.extend(render_recovery_directive_lines(directive, commands=commands))
    return lines


def recovery_directive_json(
    directive: RecoveryDirective, *, commands: Sequence[str] = ()
) -> dict[str, JsonValue]:
    """Render one frozen directive as the ``recovery`` object of a CLI-owned JSON body.

    The same facts, in the same order, as ``render_recovery_directive_lines`` (ADR-030, issue
    #741). The text is resolved here, by this renderer, from the checked-in registry; it is never
    read from the wire. ``continuation`` is the stable key a consumer should branch on; the prose
    fields are advisory and may be reworded in any release without a schema change.
    """

    body: dict[str, JsonValue] = {
        "continuation": directive.token,
        "directive": directive.directive,
    }
    if commands:
        body["commands"] = list(commands)
    if directive.guidance_uri is not None:
        body["guidance_uri"] = directive.guidance_uri
    if directive.nudge is not None:
        body["nudge"] = directive.nudge
    return body


def error_recovery_json(safe_details: object) -> dict[str, JsonValue] | None:
    """Return the ``recovery`` object for a public error's safe details, or None.

    The JSON twin of ``render_error_recovery_lines``: a claim-revision invariant and correction,
    then the continuation directive with its carried commands, pointer, and nudge.
    """

    revision, directive, commands = _resolve_error_recovery(safe_details)
    body: dict[str, JsonValue] = {}
    if revision is not None:
        body["invariant"] = revision[0]
        body["correction"] = revision[1]
    if directive is not None:
        body.update(recovery_directive_json(directive, commands=commands))
    return body or None


def local_recovery_json(reason: object) -> dict[str, JsonValue] | None:
    """Return the ``recovery`` object for a CLI lifecycle, instance, or ceremony reason, or None.

    The JSON twin of ``render_local_recovery_lines``; the lookup is the local-reason vocabulary
    only, so a protocol reason code resolves to nothing through it.
    """

    directive = directive_for(continuation_for_local_reason(reason))
    if directive is None:
        return None
    return recovery_directive_json(directive)


def render_human_error(error: PublicErrorModel) -> str:
    """Render the bounded public error fields plus any typed recovery directive."""

    if type(error) is not PublicErrorModel:
        raise TypeError("public_error_invalid")
    suffix = " (retryable)" if error.retryable else ""
    head = f"{_token(error.code)}: {error.message}{suffix}"
    return "\n".join([head, *render_error_recovery_lines(error.safe_details)])


def render_human_awaiting_human(result: CheckAwaitingHumanModel) -> str:
    """Render the nonterminal check branch as an instruction, never as a conclusion.

    No verdict or coverage appears here because none exists yet. Printing this like an ordinary
    check result is how a suspended check gets mistaken for a completed one.
    """

    if type(result) is not CheckAwaitingHumanModel:
        raise TypeError("check_result_invalid")
    continuation = result.continuation
    if result.state == "awaiting_input":
        heading = "AI-powered review: awaiting_input (review_input_required)"
        explanation = (
            "This check is paused until the complete review input is supplied. No verdict yet."
        )
    else:
        heading = "AI-powered review: awaiting_human (human_approval_required)"
        explanation = "This check is paused for trusted local privacy authority. No verdict yet."
    lines = [heading, "", explanation, "", f"  {' '.join(continuation.command)}", ""]
    if continuation.pending_id is not None:
        lines.append(f"Pending decision: {continuation.pending_id}")
    if continuation.expires_at is not None:
        lines.append(f"Expires at: {continuation.expires_at}")
    lines.append(f"Then replay the same check with request_id {continuation.replay_request_id}.")
    return "\n".join(lines)
