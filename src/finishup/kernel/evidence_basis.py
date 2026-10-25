"""Bounded, prefix-derived links for inspection, never a new proof or settlement rule (#1205)."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from typing import Final, cast

from finishup.domain.bounded_text import clip_to_limit
from finishup.domain.decision_status import compose_status_line, named
from finishup.domain.events import (
    ActionRecordedPayload,
    CheckRecordedPayload,
    ClaimRecordedPayload,
    ClaimRecordedPayloadV1_1,
    DecisionRecordedPayload,
    LedgerRecord,
    ObligationPublishedPayload,
    RedactionState,
    ResultRecordedPayload,
    redaction_targets,
)
from finishup.domain.values import JsonObject, ObligationId, ResultId
from finishup.kernel.check_standing import check_standing
from finishup.kernel.claims import effective_claim_items
from finishup.kernel.command_attempts import attempted_items_for_obligation
from finishup.kernel.correctness_advisories import correctness_advisory_index
from finishup.kernel.observed_failures import is_observed_run_record
from finishup.kernel.plan_scope import current_plan_scope
from finishup.kernel.projections import ProjectionState
from finishup.kernel.verification_freshness import (
    VerificationFreshness,
    verification_freshness,
    verification_tracked_runs,
)
from finishup.kernel.verification_link import admissible_verification_refs
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.coverage import LedgerFreshness
from finishup.protocol.models import (
    FrozenEvidenceViewModel,
    StatusEvidenceAdviceModel,
    StatusObligationEvidenceModel,
)

MAX_EVIDENCE_VIEW_BYTES = 98_304
_REFS = 8
_ROWS = 4


def evidence_view_json(view: FrozenEvidenceViewModel) -> JsonObject:
    return JsonObject(cast(dict[str, JsonValue], view.model_dump(mode="json", exclude_unset=True)))


def evidence_view_from_json(value: JsonValue) -> FrozenEvidenceViewModel:
    return FrozenEvidenceViewModel.model_validate_json(canonical_encode(value))


def evidence_view_refs(view: FrozenEvidenceViewModel) -> frozenset[str]:
    """Only structural identities, never refs recovered from participant prose."""
    refs: set[str] = set()
    notes = list(view.advisories)
    for row in view.obligations:
        refs.add(row.obligation_id)
        basis = row.basis
        refs.update(basis.action_refs)
        refs.update(basis.observed_refs)
        notes.extend(basis.advisories)
        for claim in basis.claims:
            refs.add(claim.claim_ref)
            refs.update(claim.supporting_refs)
        for result in basis.results:
            refs.add(result.result_ref)
            if result.action_ref is not None:
                refs.add(result.action_ref)
            refs.update(result.evidence_refs)
        for assessment in basis.assessments:
            refs.add(assessment.check_event_id)
            refs.update(assessment.cited_refs)
        for resolution in basis.resolution:
            refs.add(resolution.finding_ref)
            refs.update(resolution.ruling_cited_refs)
            for ref in (
                resolution.check_event_id,
                resolution.resolved_by_check_event_id,
                resolution.ruling_check_event_id,
            ):
                if ref is not None:
                    refs.add(ref)
    for note in notes:
        refs.add(note.advisory_id.split(":", 1)[0])
        refs.update(note.subject_refs)
        refs.update(note.evidence_refs or ())
        if note.response_event_id is not None:
            refs.add(note.response_event_id)
    return frozenset(refs)


def evidence_basis_by_obligation(
    view: FrozenEvidenceViewModel,
) -> dict[str, StatusObligationEvidenceModel]:
    return {row.obligation_id: row.basis for row in view.obligations}


def build_evidence_view(
    state: ProjectionState,
    records: tuple[LedgerRecord, ...],
    *,
    unavailable_event_ids: frozenset[str] = frozenset(),
    freshness: tuple[VerificationFreshness, ...] | None = None,
    tracked_runs: tuple[ResultId, ...] | None = None,
    resolution: bool = True,
) -> FrozenEvidenceViewModel:
    """Index explicit readable relations once, then bound display independently of closure.

    General task events, unscoped claims, prose similarity and nearby runs confer no scope.
    Many-to-many links keep all their declared obligations. The observation predicate is the
    existing verification-link evaluator; it certifies recorded observation, never adequacy.
    ``resolution=False`` skips the per-finding resolution evaluators (their rows stay empty) for
    a reader that needs only the run and assessment links, such as the decision line (#1139).
    """
    prefix = tuple(row for row in records if row.ledger.ingestion_sequence <= state.frontier)
    redacted_events, redacted_objects = redaction_targets(prefix)
    excluded = (
        unavailable_event_ids
        | {str(row.event_id) for row in prefix if row.redaction is not RedactionState.PRESENT}
        | {
            str(row.event_id)
            for row in prefix
            if row.event_id in redacted_events or row.payload_ref.object_id in redacted_objects
        }
        | {
            marker.removeprefix("redacted_event:")
            for marker in state.coverage_gaps
            if marker.startswith("redacted_event:")
        }
    )
    visible_prefix = tuple(row for row in prefix if str(row.event_id) not in excluded)
    readable_events = {str(row.event_id) for row in visible_prefix if row.payload is not None}
    by_event = {str(row.event_id): row for row in visible_prefix}
    freshness_rows = verification_freshness(state, prefix) if freshness is None else freshness
    tracked = frozenset(
        verification_tracked_runs(state, prefix) if tracked_runs is None else tracked_runs
    )
    fresh_by_run = {row.run_ref: row.state for row in freshness_rows}
    readable: set[str] = set()
    events: dict[str, str] = {}
    for family in (state.obligations, state.actions, state.results, state.evidence, state.claims):
        for ref, row in family.items():
            if (
                row.payload is not None
                and not row.redacted
                and row.source_frontier <= state.frontier
                and str(row.source_event_id) not in excluded
            ):
                readable.add(str(ref))
                events[str(ref)] = str(row.source_event_id)
    obligations = {key for key in state.obligations if str(key) in readable}
    scopes: dict[str, set[ObligationId]] = {str(key): {key} for key in obligations}
    omissions: Counter[ObligationId] = Counter()

    def link(ref: str, targets: Iterable[ObligationId]) -> None:
        targets = tuple(key for key in targets if key in obligations)
        if ref in readable:
            scopes.setdefault(ref, set()).update(targets)
        else:
            omissions.update(targets)

    claims = tuple(effective_claim_items(state))
    for key, row in claims:
        if row.payload is None or str(key) not in readable:
            continue
        link(str(key), row.payload.obligation_refs)
        for ref in row.payload.supporting_refs:
            if not str(ref).startswith("obl_"):
                link(str(ref), row.payload.obligation_refs)
    for key in obligations:
        payload = state.obligations[key].payload
        assert payload is not None
        for ref in payload.resolution_evidence_refs:
            link(str(ref), (key,))
    for key, row in state.actions.items():
        if row.payload is not None and str(key) in readable:
            link(str(key), row.payload.obligation_refs)
    for key, row in state.results.items():
        if row.payload is not None and str(key) in readable:
            link(str(key), scopes.get(str(row.payload.action_id), ()))
            for ref in row.payload.evidence_refs:
                link(str(ref), scopes.get(str(key), ()))
    # Source events are aliases only for the current readable record, never a general task event.
    for ref, source in events.items():
        if ref in scopes:
            scopes.setdefault(source, set()).update(scopes[ref])
    current_sources = frozenset(events.values())
    # A later obligation revision must not erase the earlier event's explicit scope. Keep such
    # event aliases as history; never reinterpret a general plan/task event as an obligation.
    for row in visible_prefix:
        payload = row.payload
        if isinstance(payload, ObligationPublishedPayload):
            targets = (payload.obligation_id,)
        elif isinstance(
            payload, ActionRecordedPayload | ClaimRecordedPayload | ClaimRecordedPayloadV1_1
        ):
            targets = payload.obligation_refs
        elif isinstance(payload, ResultRecordedPayload):
            targets = tuple(scopes.get(str(payload.result_id), ()))
        else:
            continue
        scopes.setdefault(str(row.event_id), set()).update(
            key for key in targets if key in obligations
        )

    def subjects(refs: Iterable[str]) -> set[ObligationId]:
        found: set[ObligationId] = set()
        for ref in refs:
            found.update(scopes.get(ref, ()))
        return found

    newest = sorted(
        obligations, key=lambda key: (-state.obligations[key].source_frontier, str(key))
    )
    selected = newest[:64]
    observation_rows = admissible_verification_refs(state, visible_prefix, selected, limit=None)
    observation_capped = {key for key, refs in observation_rows if len(refs) == _REFS}
    observed = {
        key: tuple(ref for ref in refs if key in scopes.get(ref, ()))
        for key, refs in observation_rows
    }
    advice: list[StatusEvidenceAdviceModel] = []
    advice_targets: dict[str, set[ObligationId]] = {}
    for note in reversed(correctness_advisory_index(visible_prefix).rows):
        omitted = 0

        def prose(value: str) -> str:
            nonlocal omitted
            clipped = clip_to_limit(value, 2048, marker=" [cut; inspect history]", ascii_only=False)
            omitted += clipped != value
            return clipped

        concern = note.concern
        subject_refs = tuple(str(ref) for ref in cast(tuple[str, ...], concern["subject_refs"]))
        admitted_subject_refs = tuple(
            ref for ref in subject_refs if ref in readable or ref in readable_events
        )
        # Resolve the full explicit relation before bounding its displayed references.
        advice_targets[note.advisory_id] = subjects(admitted_subject_refs)
        body: dict[str, object] = {
            "advisory_id": note.advisory_id,
            "summary": prose(str(concern["summary"])),
            "detail": prose(str(concern["detail"])),
            "subject_refs": admitted_subject_refs[:_REFS],
            "disposition": note.disposition.replace(" ", "_"),
        }
        omitted += len(subject_refs) - len(cast(tuple[str, ...], body["subject_refs"]))
        if note.response is not None and isinstance(note.response.payload, DecisionRecordedPayload):
            answer = note.response.payload
            assert answer.advisory_response is not None
            refs = cast(tuple[str, ...], answer.advisory_response["evidence_refs"])
            admitted = tuple(ref for ref in refs if ref in readable)
            omitted += len(refs) - len(admitted[:_REFS])
            body.update(
                response_event_id=str(note.response.event_id),
                reason=prose(answer.rationale),
                evidence_refs=admitted[:_REFS],
            )
        body["omitted"] = omitted
        advice.append(StatusEvidenceAdviceModel.model_validate(body))

    assessments: dict[ObligationId, list[dict[str, object]]] = {}
    rulings: dict[str, tuple[str, str, tuple[str, ...]]] = {}
    standing = check_standing(state, prefix)

    def applicability(event: str) -> str:
        return (
            "current"
            if standing.check_record is not None
            and str(standing.check_record.event_id) == event
            and not standing.superseded
            and not standing.bounds_conclusion
            and state.freshness is LedgerFreshness.CURRENT
            else "historical"
        )

    for record in reversed(visible_prefix):
        check = record.payload
        if not isinstance(check, CheckRecordedPayload):
            continue
        for ruling in check.prior_finding_verdicts:
            rulings.setdefault(
                str(ruling.finding_id),
                (
                    str(record.event_id),
                    ruling.verdict,
                    tuple(
                        ref
                        for ref in ruling.cited_refs
                        if ref in readable or ref in readable_events
                    ),
                ),
            )
        for assessment in check.verified:
            refs = cast(tuple[str, ...], assessment["cited_refs"])
            targets = subjects(refs)
            admitted = tuple(ref for ref in refs if ref in readable or ref in readable_events)
            if not admitted:
                continue
            body = {
                "check_event_id": str(record.event_id),
                "checked_frontier": str(check.subject_frontier.sequence),
                "applicability": (
                    applicability(str(record.event_id))
                    if all(
                        ref not in scopes or ref in readable or ref in current_sources
                        for ref in refs
                    )
                    else "historical"
                ),
                "requirement_or_claim": clip_to_limit(
                    str(assessment["requirement_or_claim"]),
                    2048,
                    marker=" [cut; inspect history]",
                    ascii_only=False,
                ),
                "verdict": str(assessment["verdict"]),
                "cited_refs": admitted,
                **(
                    {
                        "snippet": clip_to_limit(
                            str(assessment["snippet"]),
                            2048,
                            marker=" [cut; inspect history]",
                            ascii_only=False,
                        )
                    }
                    if assessment.get("snippet")
                    else {}
                ),
            }
            for key in targets:
                assessments.setdefault(key, []).append(body)
                omissions[key] += (
                    len(refs)
                    - len(admitted)
                    + sum(
                        str(body.get(field, "")) != str(assessment.get(field, ""))
                        for field in ("requirement_or_claim", "snippet")
                    )
                )

    # These are the existing evaluators used by respond and closure, with this exact prefix.
    from finishup.kernel.finding_resolution import finding_resolution_attempt
    from finishup.kernel.finding_todo import FindingTodoState, finding_todo_state

    resolutions: dict[ObligationId, list[dict[str, object]]] = {}
    resolution_counts: Counter[ObligationId] = Counter()
    selected_obligations = frozenset(selected)
    for key, row in sorted(
        state.findings.items() if resolution else (),
        key=lambda item: (-item[1].source_frontier, str(item[0])),
    ):
        if row.payload is None or row.redacted or row.source_frontier > state.frontier:
            continue
        targets = subjects(str(ref) for ref in row.payload.subject_refs) & selected_obligations
        if not targets:
            continue
        if str(row.source_event_id) in excluded:
            omissions.update(targets)
            continue
        admitted_targets = {key for key in targets if resolution_counts[key] < _ROWS}
        omissions.update(targets - admitted_targets)
        if not admitted_targets:
            continue
        # Each evaluator reads the prefix. Reserve bounded display slots before invoking it,
        # including when its check is unavailable, rather than evaluating all historical findings.
        resolution_counts.update(admitted_targets)
        from finishup.kernel.self_verification import self_verification_evaluation

        attempt = finding_resolution_attempt(state, key, prefix)
        if attempt is not None and str(attempt.check_event_id) in excluded:
            omissions.update(admitted_targets)
            continue
        terminal = finding_todo_state(state, key) is not FindingTodoState.OPEN
        refusal, blocking = (
            ("finding_terminal", ())
            if terminal
            else self_verification_evaluation(state, key, prefix, attempt=attempt)
        )
        ruling = rulings.get(str(key))
        body = {
            "finding_ref": str(key),
            "check_event_id": None if attempt is None else str(attempt.check_event_id),
            "check_could_resolve": attempt is not None and attempt.could_resolve,
            "checked_frontier": None
            if attempt is None or attempt.subject_sequence is None
            else str(attempt.subject_sequence),
            "reviewer_verdict": None if ruling is None else ruling[1],
            "ruling_check_event_id": None if ruling is None else ruling[0],
            "ruling_applicability": None if ruling is None else applicability(ruling[0]),
            "ruling_cited_refs": () if ruling is None else ruling[2],
            "resolved_by_check_event_id": row.resolved_by_check_event_id,
            "reasons": () if attempt is None else attempt.reasons[:16],
            "self_verified_available": refusal is None,
            "self_verified_refusal": refusal,
            "blocking_reasons": blocking[:16],
        }
        for obligation in admitted_targets:
            resolutions.setdefault(obligation, []).append(body)
            omissions[obligation] += max(0, len(blocking) - 16) + (
                0 if attempt is None else max(0, len(attempt.reasons) - 16)
            )

    claim_rows: dict[ObligationId, list[dict[str, object]]] = {}
    result_rows: dict[ObligationId, list[dict[str, object]]] = {}
    action_refs: dict[ObligationId, list[str]] = {}
    for key, row in claims:
        if row.payload is not None and str(key) in readable:
            for obligation in scopes.get(str(key), ()):
                claim_rows.setdefault(obligation, []).append(
                    {
                        "claim_ref": str(key),
                        "supporting_refs": tuple(
                            str(ref) for ref in row.payload.supporting_refs if str(ref) in readable
                        )[:_REFS],
                    }
                )
                omissions[obligation] += max(0, len(row.payload.supporting_refs) - _REFS)
    for key in state.actions:
        for obligation in scopes.get(str(key), ()):
            action_refs.setdefault(obligation, []).append(str(key))
    # Snapshot maps normalize identity order. Select the newest linked results explicitly so
    # the cap preserves the same evidence before and after projection serialization.
    for key, row in sorted(
        state.results.items(), key=lambda item: (-item[1].source_frontier, str(item[0]))
    ):
        if row.payload is None or str(key) not in readable:
            continue
        source = by_event.get(str(row.source_event_id))
        action = state.actions.get(row.payload.action_id)
        action_source = None if action is None else by_event.get(str(action.source_event_id))
        is_observed = any(
            record is not None and is_observed_run_record(record)
            for record in (source, action_source)
        )
        verification = row.payload.verification
        for obligation in scopes.get(str(key), ()):
            result_rows.setdefault(obligation, []).append(
                {
                    "result_ref": str(key),
                    "action_ref": str(row.payload.action_id)
                    if str(row.payload.action_id) in readable
                    else None,
                    "outcome": row.payload.outcome.value,
                    "evidence_refs": tuple(
                        str(ref) for ref in row.payload.evidence_refs if str(ref) in readable
                    )[:_REFS],
                    "observed": is_observed,
                    "verification_declared": verification is not None,
                    "freshness": fresh_by_run.get(key, "current") if key in tracked else "legacy",
                    **(
                        {
                            "verification": {
                                "data_source": verification.data_source.value,
                                "cases": verification.cases,
                                "failing": verification.failing,
                                "tuned_on_these_cases": verification.tuned_on_these_cases,
                            }
                        }
                        if verification is not None
                        else {}
                    ),
                }
            )
            omissions[obligation] += max(0, len(row.payload.evidence_refs) - _REFS)
    rows: list[dict[str, object]] = []
    for key in selected:
        notes = [note for note in advice if key in advice_targets[note.advisory_id]]
        lists: dict[str, tuple[Sequence[object], int]] = {
            "claims": (list(claim_rows.get(key, ())), _REFS),
            "action_refs": (sorted(action_refs.get(key, ())), _REFS),
            "results": (list(result_rows.get(key, ())), _REFS),
            "observed_refs": (list(observed.get(key, ())), _REFS),
            "advisories": (
                [note.model_dump(mode="json", exclude_unset=True) for note in notes],
                _ROWS,
            ),
            "assessments": (list(assessments.get(key, ())), _ROWS),
            "resolution": (list(resolutions.get(key, ())), _ROWS),
        }
        basis: dict[str, object] = {name: values[:cap] for name, (values, cap) in lists.items()}
        basis.update(
            availability="recorded",
            observed_refs_capped=key in observation_capped,
            omitted=omissions[key]
            + sum(max(0, len(values) - cap) for values, cap in lists.values()),
        )
        rows.append({"obligation_id": str(key), "basis": basis})
    omitted = len(obligations) - len(rows) + max(0, len(advice) - _ROWS)
    # The complete local/frozen view has a byte bound as well as item bounds. Dropped rows are
    # explicit; neither this cap nor any of the per-field caps is read by closure evaluators.
    while True:
        view = FrozenEvidenceViewModel.model_validate(
            {"obligations": rows, "advisories": advice[:_ROWS], "omitted": omitted}
        )
        if len(canonical_encode(evidence_view_json(view))) <= MAX_EVIDENCE_VIEW_BYTES:
            return view
        if rows:
            rows.pop()
        else:
            advice.pop()
        omitted += 1


# Each linked obligation's newest linked result, in display order (#1139).
_RUN_PARTS: Final = (
    ("success", "success"),
    ("failure", "failed or partial"),
    ("stale", "stale"),
    ("possibly_stale", "possibly stale"),
    ("unknown", "unknown outcome"),
    ("none", "no linked run"),
    ("unlisted", "not listed here"),
)


def _latest_run(basis: StatusObligationEvidenceModel | None) -> str:
    if basis is None:
        return "unlisted"
    if not basis.results:
        return "none"
    latest = basis.results[0]  # The view lists linked results newest first.
    if latest.outcome in {"failure", "partial"}:
        return "failure"
    if latest.freshness == "stale":
        return "stale"
    if latest.outcome == "unknown":
        return "unknown"
    return "possibly_stale" if latest.freshness == "unknown" else "success"


def decision_status_line(
    state: ProjectionState,
    records: tuple[LedgerRecord, ...],
    *,
    fix_or_decline: int = 0,
    advice_unanswered: int = 0,
    reviewer: bool = True,
    freshness: tuple[VerificationFreshness, ...] | None = None,
    tracked_runs: tuple[ResultId, ...] | None = None,
) -> str:
    """One counted line of what the ledger records at the decision point (#1139).

    Records, not correctness: the obligations in the current plan by status, each one's newest
    linked result by outcome and freshness (``build_evidence_view``, as ``status
    view=obligations`` shows it), requested items with no recorded attempt, the current check's
    reviewer assessments that were not supported or not assessable, unanswered advice and open
    fix-or-decline items. Zero-count parts are omitted and at most two ids are named per part.
    Closed words, counts and service-minted ids only. ``reviewer=False`` keeps only the ledger
    counts (the receipt carries the rest in its own sections).
    """

    if not state.obligations:
        return ""
    view = build_evidence_view(
        state, records, freshness=freshness, tracked_runs=tracked_runs, resolution=False
    )
    bases = evidence_basis_by_obligation(view)
    scope = current_plan_scope(state.plans, state.coverage_gaps)
    active = sorted(
        str(key)
        for key in (
            scope.effective_obligation_refs
            if scope.has_plan and scope.effective_obligation_refs is not None
            else state.obligations
        )
    )
    statuses: Counter[str] = Counter()
    runs: dict[str, list[str]] = {key: [] for key, _ in _RUN_PARTS}
    unattempted_items = 0
    unattempted: list[str] = []
    for ref in active:
        record = state.obligations.get(ObligationId(ref))
        payload = None if record is None else record.payload
        if payload is None:
            statuses["unreadable"] += 1
            continue
        statuses[payload.status.value] += 1
        runs[_latest_run(bases.get(ref))].append(ref)
        attempted = attempted_items_for_obligation(state, ObligationId(ref))
        missing = sum(item.value not in attempted for item in payload.requested_items)
        if missing:
            unattempted_items += missing
            unattempted.append(ref)
    status_text = ", ".join(
        f"{statuses[key]} {label}"
        for key, label in (
            ("resolved", "resolved"),
            ("open", "open"),
            ("acknowledged_not_done", "acknowledged not done"),
            ("unreadable", "unreadable"),
        )
        if statuses[key]
    )
    run_text = ", ".join(
        part
        for key, label in _RUN_PARTS
        if (part := named(len(runs[key]), label, () if key == "success" else runs[key]))
    )
    parts = [
        f"{len(active)} obligation{'' if len(active) == 1 else 's'}"
        + (f" ({status_text})" if status_text else ""),
        f"latest linked run: {run_text}" if run_text else "",
        named(
            unattempted_items,
            "requested item" + ("" if unattempted_items == 1 else "s") + " unattempted",
            unattempted,
        ),
    ]
    if reviewer:
        assessed: dict[tuple[str, str, str], str] = {}
        for row in view.obligations:
            for assessment in row.basis.assessments:
                if assessment.applicability == "current":
                    key = (
                        str(assessment.check_event_id),
                        str(assessment.requirement_or_claim),
                        ",".join(assessment.cited_refs),
                    )
                    assessed[key] = assessment.verdict
        verdicts = Counter(assessed.values())
        reviewer_text = ", ".join(
            f"{verdicts[key]} {label}"
            for key, label in (
                ("not_supported", "not supported"),
                ("not_assessable", "not assessable"),
            )
            if verdicts[key]
        )
        parts.extend(
            (
                f"reviewer (current check): {reviewer_text}" if reviewer_text else "",
                f"advice unanswered: {advice_unanswered}" if advice_unanswered > 0 else "",
                f"fix-or-decline: {fix_or_decline}" if fix_or_decline > 0 else "",
            )
        )
    return compose_status_line(parts)
