"""Pure canonical receipt assembly from one complete frozen application context."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from enum import Enum
from types import MappingProxyType
from typing import Final, Literal, cast

from finishup.domain.bounded_text import clip_to_limit
from finishup.domain.check_totals import render_check_totals
from finishup.domain.events import (
    AcceptedEvent,
    CheckRecordedPayload,
    ClaimKind,
    ClaimRecordedPayloadV1_1,
    LedgerRecord,
    NoObligationsReason,
    ObligationChangeKind,
    ObligationStatus,
    ResponseRecordedPayload,
    ReviewMode,
    is_lineage_service_stamped,
    is_observation_authored,
)
from finishup.domain.findings import (
    FINDING_KIND_TRAITS,
    Finding,
    FindingKind,
    FindingOrigin,
    ResponseDisposition,
    SemanticProvenance,
    rank_key,
)
from finishup.domain.receipts import (
    CHECK_CURRENT_AS_OF_EARLIER_FRONTIER_GAP,
    CHECK_TIME_CHANGE_RESOLUTION_UNVERIFIED_GAP,
    COMPLETION_CLAIM_OUTSIDE_PLAN_GAP,
    COMPLETION_PLAN_NOT_CLAIMED_GAP,
    COMPLETION_SCOPE_DECLARED_NONE_GAP,
    COMPLETION_SCOPE_UNDECLARED_GAP,
    COORDINATOR_FAILURE_LIMITATION,
    DEFERRED_BEFORE_FIRST_EDIT_TEXT,
    OPTIONAL_SEMANTIC_REVIEW_REGISTRATION_DRIFT_GAP,
    PREEXISTING_TEST_INFORMATIONAL_GAPS,
    SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP,
    SEMANTIC_REVIEW_DEFERRED_BEFORE_FIRST_EDIT_GAP,
    SEMANTIC_REVIEW_NOT_CONFIGURED_GAP,
    SEMANTIC_REVIEW_NOT_REQUESTED_GAP,
    SEMANTIC_REVIEW_SKIPPED_INSUFFICIENT_PACKET_GAP,
    ReceiptChildFinding,
    ReceiptChildOutcome,
    ReceiptChildren,
    ReceiptConclusion,
    ReceiptConclusionBasis,
    ReceiptConclusionReason,
    ReceiptDisclosure,
    ReceiptDocument,
    ReceiptDuplicateLink,
    ReceiptGap,
    ReceiptGapEffect,
    ReceiptGapStatus,
    ReceiptObligation,
    ReceiptObligationStatus,
    ReceiptRedaction,
    ReceiptRedactionCategory,
    ReceiptRedactionReason,
    ReceiptResponse,
    ReceiptSection,
    ReceiptSectionKey,
    ReceiptSemanticWithheldItem,
    ReceiptVersionSlice,
    check_time_change_gap_sentence,
    receipt_document_carries_terminal_sections,
)
from finishup.domain.review_input_render import (
    render_review_input_manifest_compat_line,
    render_review_input_manifest_coverage_note,
)
from finishup.domain.reviewer_reads import render_reviewer_lines, reviewer_record_from_wire
from finishup.domain.task_fact_tokens import (
    DELIVERABLE_REFERENCES_AMBIGUOUS_NAME_GAP,
    DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP,
    undeclared_reference_variants,
)
from finishup.domain.task_statement import (
    TASK_STATEMENT_NOT_AUTHORIZED_GAP,
    TASK_STATEMENT_NOT_SUPPLIED_GAP,
    TASK_STATEMENT_UNAVAILABLE_GAP,
    TaskStatementSource,
    current_task_statement,
    may_carry_task_statement,
    task_statement_gap_detail,
)
from finishup.domain.values import (
    Actor,
    ClaimId,
    EventId,
    EvidenceId,
    FindingId,
    Frontier,
    ObligationId,
    ReceiptId,
    ResultId,
    SessionId,
    TaskId,
    Timestamp,
    finding_id,
)
from finishup.kernel.check_standing import CheckStanding, LaterRecord
from finishup.kernel.claim_verification import (
    UNRESOLVED_VERIFICATION_GAP,
    claim_verification_report,
    unresolved_verification_obligations,
)
from finishup.kernel.claims import (
    claim_discloses_result,
    effective_claim_items,
    result_is_relevant_to_claim,
)
from finishup.kernel.closure_class import (
    FINDING_BASES,
    FindingClosure,
    FindingClosureClass,
    ObligationClosure,
    ObligationClosureClass,
    ReceiptEffect,
    closure_counts,
    is_bookkeeping_finding,
    obligation_closures,
)
from finishup.kernel.closure_readiness import freshness_review_used, premise_disputed_finding_ids
from finishup.kernel.command_attempts import command_attempts
from finishup.kernel.completion_scope import (
    SCOPE_REPAIR,
    completion_scope_differences,
)
from finishup.kernel.delivered_set import (
    ambiguous_reference_count,
    deliverable_lineage,
    undeclared_reference_rows,
)
from finishup.kernel.deterministic_checks import (
    CALLER_DIGEST_PROVENANCE_GAPS,
    CaseAvailabilityFacts,
    CaseGap,
)
from finishup.kernel.deterministic_scope import commands_complete
from finishup.kernel.fact_lineage import FactLineage, lineage_texts
from finishup.kernel.finding_resolution import (
    finding_resolution_explanation,
    issue_key,
    unverified_resolution_finding_ids,
)
from finishup.kernel.finding_retirement import is_observed_failed_command_finding
from finishup.kernel.gap_effect import GapContext, gap_effect, judge_gaps
from finishup.kernel.later_material import LaterMaterialClass, counted_later_material
from finishup.kernel.lineage import LineageEvaluation, LineageRollupState
from finishup.kernel.observed_failures import (
    ObservedFailureState,
    observed_event_ids_from_records,
    observed_failure_states,
)
from finishup.kernel.plan_scope import CurrentPlanScope, current_plan_scope
from finishup.kernel.projections import (
    ObligationProjectionRecord,
    ProjectionRecord,
    ProjectionState,
)
from finishup.kernel.receipt_prediction import (
    AppliedCheck,
    ClosureBasis,
    LineageBasis,
    PredictionConclusion,
    ReceiptPrediction,
    predict_receipt_conclusion,
)
from finishup.kernel.reducers import is_material_event_family
from finishup.kernel.review_mode import ReviewModeSwitch, review_mode_switches
from finishup.kernel.task_facts import (
    acknowledged_obligation_ids,
    disclosure_declarations,
    task_fact_signals,
)
from finishup.protocol.coverage import LEDGER_FRESHNESS_ORDER, Coverage, PublicationChannel, weakest
from finishup.protocol.models import (
    ReceiptInclude,
    ReceiptRedactionProfile,
    SemanticReason,
    SemanticStatus,
)
from finishup.protocol.readiness_text import reason_phrases

__all__ = [
    "CheckSuffixClass",
    "ReceiptBuildContext",
    "ReceiptFindingState",
    "build_receipt",
    "closure_basis_from_context",
    "predict_context_conclusion",
    "route_did_not_require_review",
]

_CONTEXT_INVALID: Final = "receipt_build_context_invalid"
_CHECK_ABSENCE_GAPS: Final = frozenset(
    {"check_not_recorded", "check_not_applicable", "check_payload_unavailable"}
)
_COMPLETION_SCOPE_GAPS: Final = frozenset(
    {COMPLETION_SCOPE_DECLARED_NONE_GAP, COMPLETION_SCOPE_UNDECLARED_GAP}
)
_SECTION_TITLES: Final = {
    ReceiptSectionKey.SUMMARY: "Summary",
    ReceiptSectionKey.OUTSTANDING_WORK: "Outstanding work",
    ReceiptSectionKey.FINDINGS_AND_DISPOSITIONS: "Findings",
    ReceiptSectionKey.EVIDENCE_AND_CLAIM_BASIS: "Evidence basis",
    ReceiptSectionKey.LIMITATIONS_AND_COVERAGE: "Limitations",
    ReceiptSectionKey.VERSION_AND_POLICY_IDENTITY: "Versions and policy",
}
_SECTION_KEYS: Final = {
    ReceiptInclude.SUMMARY: (
        ReceiptSectionKey.SUMMARY,
        ReceiptSectionKey.LIMITATIONS_AND_COVERAGE,
        ReceiptSectionKey.VERSION_AND_POLICY_IDENTITY,
    ),
    ReceiptInclude.STANDARD: (
        ReceiptSectionKey.SUMMARY,
        ReceiptSectionKey.OUTSTANDING_WORK,
        ReceiptSectionKey.FINDINGS_AND_DISPOSITIONS,
        ReceiptSectionKey.LIMITATIONS_AND_COVERAGE,
        ReceiptSectionKey.VERSION_AND_POLICY_IDENTITY,
    ),
    ReceiptInclude.FULL: (
        ReceiptSectionKey.SUMMARY,
        ReceiptSectionKey.OUTSTANDING_WORK,
        ReceiptSectionKey.FINDINGS_AND_DISPOSITIONS,
        ReceiptSectionKey.EVIDENCE_AND_CLAIM_BASIS,
        ReceiptSectionKey.LIMITATIONS_AND_COVERAGE,
        ReceiptSectionKey.VERSION_AND_POLICY_IDENTITY,
    ),
}


def _ascii_key(value: str) -> bytes:
    try:
        return value.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(_CONTEXT_INVALID) from exc


def _sorted_unique[T: str](values: Iterable[T]) -> tuple[T, ...]:
    return tuple(sorted(set(values), key=_ascii_key))


# The receipt document holds at most this many of each row kind, and a section at most this many
# items. A task past them used to fail to build any receipt at all (INVALID_REQUEST "The receipt
# request is invalid", or STORAGE_CORRUPT from the selection guards) -- the agent could never close
# a long-lived task (tb4n3 RC-2, A6). The builder now keeps the rows that matter most, in a
# stable order, and says how many it left out.
_DOCUMENT_ROW_CAP: Final = 100
_GAP_ROW_CAP: Final = 64
_SECTION_ITEM_CAP: Final = 64
_SECTION_BODY_CAP: Final = 32_768


def _keep_by_rank[T](
    values: tuple[T, ...],
    cap: int,
    rank: Callable[[T], int],
    *,
    cap_rank: int | None = None,
) -> tuple[tuple[T, ...], int]:
    """Keep the ``cap`` best-ranked values in their original order; return them and the rest.

    With ``cap_rank`` the cap applies to the values of that rank alone and every other value is
    kept (used to bound one kind of row without touching the rest).
    """

    if cap_rank is not None:
        capped = [index for index, value in enumerate(values) if rank(value) == cap_rank]
        if len(capped) <= cap:
            return values, 0
        dropped = frozenset(capped[cap:])
        return (
            tuple(value for index, value in enumerate(values) if index not in dropped),
            len(dropped),
        )
    if len(values) <= cap:
        return values, 0
    best = frozenset(
        sorted(range(len(values)), key=lambda index: (rank(values[index]), index))[:cap]
    )
    return tuple(value for index, value in enumerate(values) if index in best), len(values) - cap


def _omitted_rows_sentence(omitted: Mapping[str, int]) -> str:
    named = [
        f"{count} {noun if count == 1 else noun + 's'}"
        for noun, count in omitted.items()
        if count > 0
    ]
    if not named:
        return ""
    return (
        " Not listed in this receipt (the document holds at most "
        f"{_DOCUMENT_ROW_CAP} rows of a kind, {_GAP_ROW_CAP} gaps): {', '.join(named)}. "
        "Unresolved actionable findings and open obligations are listed first, and the coverage "
        "list still names every limitation; status lists every row."
    )


def _finish_section(body: str, items: tuple[str, ...]) -> tuple[str, tuple[str, ...]]:
    """Bound one section: at most the item cap, a visible count of the rest, a marked body cut."""

    note = ""
    if len(items) > _SECTION_ITEM_CAP:
        note = (
            f" {len(items) - _SECTION_ITEM_CAP} more item(s) are not listed here; "
            "status lists every row."
        )
        items = items[:_SECTION_ITEM_CAP]
    if len(body) + len(note) > _SECTION_BODY_CAP:
        body = clip_to_limit(
            body, _SECTION_BODY_CAP - len(note), marker=" [section text cut]", ascii_only=False
        )
    return body + note, items


@dataclass(frozen=True, slots=True)
class ReceiptFindingState:
    finding_id: FindingId
    resolved: bool
    # Issue #905 terminal states. ``acknowledged_not_done`` stays unresolved and blocking;
    # ``rejection_accepted`` stays unresolved but no longer blocks a clean conclusion. Both are
    # disclosed by id in their own receipt sections. ``self_verified`` (issue #984) stays
    # unresolved, is not agent work, and caps the conclusion at ``insufficient_coverage``.
    acknowledged_not_done: bool = False
    rejection_accepted: bool = False
    self_verified: bool = False
    # Issue #1020 (ADR-040): the reviewer repeated it over the agent's reasoned rejection without
    # newer material. Unresolved, not agent work; caps the conclusion like ``self_verified``.
    disputed_after_rebuttal: bool = False
    # Issue #996: the earlier finding a holding ``duplicate_of`` link names. The flags above are
    # then the ones derived from it (``finding_todo``); the link is disclosed by ids.
    duplicate_of_finding_id: FindingId | None = None
    # tb4n3 RC-3 (ADR-046): the finding's closure class, basis and receipt effect, computed once by
    # ``kernel.closure_class`` from the same projection. A hand-built state without it is read
    # from the flags above (``closure_basis_from_context``).
    closure: FindingClosure | None = None

    def __post_init__(self) -> None:
        if self.closure is not None and (
            type(self.closure) is not FindingClosure or self.closure.finding_id != self.finding_id
        ):
            raise ValueError(_CONTEXT_INVALID)
        try:
            object.__setattr__(self, "finding_id", finding_id(self.finding_id))
            if self.duplicate_of_finding_id is not None:
                object.__setattr__(
                    self, "duplicate_of_finding_id", finding_id(self.duplicate_of_finding_id)
                )
        except ValueError as exc:
            raise ValueError(_CONTEXT_INVALID) from exc
        if self.duplicate_of_finding_id == self.finding_id:
            raise ValueError(_CONTEXT_INVALID)
        if (
            type(self.resolved) is not bool
            or type(self.acknowledged_not_done) is not bool
            or type(self.rejection_accepted) is not bool
            or type(self.self_verified) is not bool
            or type(self.disputed_after_rebuttal) is not bool
            or self.resolved
            + self.acknowledged_not_done
            + self.rejection_accepted
            + self.self_verified
            + self.disputed_after_rebuttal
            > 1
        ):
            raise ValueError(_CONTEXT_INVALID)


def _issue_key(finding: Finding) -> tuple[object, ...]:
    return issue_key(finding)


def _projection_records(projection: ProjectionState) -> tuple[ProjectionRecord[object], ...]:
    records: list[ProjectionRecord[object]] = []
    for collection in (
        projection.plans,
        projection.obligations,
        projection.decisions,
        projection.assignments,
        projection.actions,
        projection.results,
        projection.evidence,
        projection.claims,
        projection.findings,
        projection.responses,
    ):
        records.extend(cast(Iterable[ProjectionRecord[object]], collection.values()))
    return tuple(records)


def _validate_availability(context: ReceiptBuildContext) -> None:
    gaps_by_marker = {gap.marker: gap for gap in context.gaps}
    projection_records = _projection_records(context.projection)
    for source_event_id in context.availability.unavailable_event_ids:
        marker = f"unavailable_event:{source_event_id}"
        gap = gaps_by_marker.get(marker)
        if (
            gap is None
            or gap.code != "event_payload_unavailable"
            or gap.subject_refs != (source_event_id,)
            or not any(
                record.source_event_id == source_event_id and record.payload is None
                for record in projection_records
            )
        ):
            raise ValueError(_CONTEXT_INVALID)
    for unavailable in context.availability.unavailable_captured_objects:
        marker = (
            f"unavailable_captured_object:{unavailable.source_event_id}:{unavailable.object_id}"
        )
        gap = gaps_by_marker.get(marker)
        evidence_matches = tuple(
            record
            for record in context.projection.evidence.values()
            if record.source_event_id == unavailable.source_event_id
            and record.payload is not None
            and record.payload.captured_object_id == unavailable.object_id
        )
        if (
            gap is None
            or gap.code != "captured_object_unavailable"
            or gap.subject_refs != (unavailable.source_event_id,)
            or len(evidence_matches) != 1
        ):
            raise ValueError(_CONTEXT_INVALID)


def _validate_finding_states(context: ReceiptBuildContext) -> None:
    ids = tuple(state.finding_id for state in context.finding_states)
    if len(ids) != len(set(ids)):
        raise ValueError(_CONTEXT_INVALID)
    findings: list[Finding] = []
    for state in context.finding_states:
        record = context.projection.findings.get(state.finding_id)
        if record is None or record.payload is None:
            raise ValueError(_CONTEXT_INVALID)
        findings.append(record.payload)
    typed = tuple(findings)
    if typed != tuple(sorted(typed, key=rank_key)):
        raise ValueError(_CONTEXT_INVALID)
    if len({_issue_key(finding) for finding in typed}) != len(typed):
        raise ValueError(_CONTEXT_INVALID)

    newest_readable: dict[tuple[object, ...], tuple[int, FindingId]] = {}
    for current_id, record in context.projection.findings.items():
        if record.payload is None:
            continue
        key = _issue_key(record.payload)
        candidate = (record.source_frontier, current_id)
        previous = newest_readable.get(key)
        if previous is None or candidate > previous:
            newest_readable[key] = candidate
    for finding in typed:
        newest = newest_readable[_issue_key(finding)][1]
        if newest != finding.finding_id:
            raise ValueError(_CONTEXT_INVALID)


def _validate_applicable_check(context: ReceiptBuildContext) -> None:
    latest = context.projection.latest_tested_state
    check = context.applicable_check
    if check is None:
        if not (_CHECK_ABSENCE_GAPS & set(context.coverage.known_gaps)):
            raise ValueError(_CONTEXT_INVALID)
        # The earlier-frontier gap qualifies a check that does contribute; it can never stand in
        # for one that is absent, or the limitations wording would describe a check that is gone.
        if CHECK_CURRENT_AS_OF_EARLIER_FRONTIER_GAP in context.coverage.known_gaps:
            raise ValueError(_CONTEXT_INVALID)
        return
    if latest is None:
        raise ValueError(_CONTEXT_INVALID)
    if (
        check.subject_frontier != latest.subject_frontier
        or check.subject_frontier.sequence > context.subject_frontier.sequence
        or check.verdict is not latest.verdict
        or check.returned_finding_ids != latest.returned_finding_ids
        or check.suppressed_count != latest.suppressed_count
        or check.coverage != latest.coverage
    ):
        raise ValueError(_CONTEXT_INVALID)


class CheckSuffixClass(Enum):
    """Bounded classification of the material records accepted after an attributable check.

    The application derives this from the same authorship-aware rule that keeps the check
    applicable (issue #361), so the receipt explanation can name what actually followed the check
    instead of assuming a response-only suffix (issue #657). It is render context only: it is not a
    wire field, not a gap code, and never changes the applicability decision.
    """

    RESPONSES_ONLY = "responses_only"
    OBSERVATIONS_ONLY = "observations_only"
    MIXED = "mixed"


@dataclass(frozen=True, slots=True)
class ReceiptBuildContext:
    projection: ProjectionState
    subject_frontier: Frontier
    availability: CaseAvailabilityFacts
    coverage: Coverage
    gaps: tuple[CaseGap, ...]
    finding_states: tuple[ReceiptFindingState, ...]
    applicable_check: CheckRecordedPayload | None
    lineage: LineageEvaluation | None = None
    check_suffix: CheckSuffixClass | None = None
    records: tuple[LedgerRecord, ...] = ()
    # tb4n3 RC-6: what followed the latest check and why it did or did not supersede it
    # (``kernel.check_standing``): the superseding record, the records the earlier-frontier code
    # counts, and the number of later records proved harmless by class. Render context only.
    check_standing: CheckStanding | None = None
    # Issue #1017: gap codes an earlier check carried and the latest check no longer carries,
    # each with the subject frontier of the first check without it, sorted by code. They stay in
    # ``coverage`` (retained findings still carry them) but never bound the conclusion.
    historical_gaps: tuple[tuple[str, Frontier], ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.projection) is not ProjectionState
            or type(self.subject_frontier) is not Frontier
            or type(self.availability) is not CaseAvailabilityFacts
            or type(self.coverage) is not Coverage
            or type(self.gaps) is not tuple
            or any(type(gap) is not CaseGap for gap in self.gaps)
            or type(self.finding_states) is not tuple
            or any(type(state) is not ReceiptFindingState for state in self.finding_states)
            or (
                self.applicable_check is not None
                and type(self.applicable_check) is not CheckRecordedPayload
            )
            or (self.lineage is not None and type(self.lineage) is not LineageEvaluation)
            or (self.check_suffix is not None and type(self.check_suffix) is not CheckSuffixClass)
            or (self.check_standing is not None and type(self.check_standing) is not CheckStanding)
        ):
            raise ValueError(_CONTEXT_INVALID)
        # A suffix class describes records that followed an attributable check; without that
        # check and its earlier-frontier gap there is nothing for the class to describe.
        if self.check_suffix is not None and (
            self.applicable_check is None
            or CHECK_CURRENT_AS_OF_EARLIER_FRONTIER_GAP not in self.coverage.known_gaps
        ):
            raise ValueError(_CONTEXT_INVALID)
        expected_frontier = Frontier(self.projection.frontier, self.projection.head_digest)
        if self.subject_frontier != expected_frontier:
            raise ValueError(_CONTEXT_INVALID)
        ordered_gaps = tuple(
            sorted(
                self.gaps,
                key=lambda gap: (
                    _ascii_key(gap.marker),
                    tuple(_ascii_key(ref) for ref in gap.subject_refs),
                ),
            )
        )
        if self.gaps != ordered_gaps or len({gap.marker for gap in self.gaps}) != len(self.gaps):
            raise ValueError(_CONTEXT_INVALID)
        if set(self.coverage.known_gaps) != {gap.code for gap in self.gaps}:
            raise ValueError(_CONTEXT_INVALID)
        if (
            type(self.historical_gaps) is not tuple
            or any(
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or item[0] not in self.coverage.known_gaps
                or type(item[1]) is not Frontier
                or item[1].sequence > self.subject_frontier.sequence
                for item in self.historical_gaps
            )
            or [item[0] for item in self.historical_gaps]
            != sorted({item[0] for item in self.historical_gaps}, key=_ascii_key)
            # Only a code that reached the receipt solely through retained-finding coverage can
            # be history; a case, check or lineage gap with the same code is always live.
            or any(
                gap.marker != f"retained_finding_coverage:{gap.code}"
                for gap in self.gaps
                if gap.code in {item[0] for item in self.historical_gaps}
            )
        ):
            raise ValueError(_CONTEXT_INVALID)
        if (
            LEDGER_FRESHNESS_ORDER[self.coverage.ledger_freshness]
            > LEDGER_FRESHNESS_ORDER[self.projection.freshness]
        ):
            raise ValueError(_CONTEXT_INVALID)
        for state in self.finding_states:
            record = self.projection.findings.get(state.finding_id)
            if record is None or record.payload is None:
                raise ValueError(_CONTEXT_INVALID)
            # A resolved row is history: a later qualifying check proved its issue absent, so its
            # coverage no longer bounds the conclusion (issue #912). Current rows still must.
            if state.resolved:
                continue
            if weakest(self.coverage, record.payload.coverage) != self.coverage:
                raise ValueError(_CONTEXT_INVALID)
        if self.applicable_check is not None:
            if weakest(self.coverage, self.applicable_check.coverage) != self.coverage:
                raise ValueError(_CONTEXT_INVALID)
        if (
            self.lineage is not None
            and weakest(self.coverage, self.lineage.coverage) != self.coverage
        ):
            raise ValueError(_CONTEXT_INVALID)
        _validate_availability(self)
        _validate_finding_states(self)
        _validate_applicable_check(self)


def _receipt_obligation_status(record: ObligationProjectionRecord) -> ReceiptObligationStatus:
    if record.payload is None:
        raise ValueError(_CONTEXT_INVALID)
    if record.plan_change is ObligationChangeKind.SUPERSEDED:
        return ReceiptObligationStatus.SUPERSEDED
    if record.plan_change is ObligationChangeKind.WAIVED:
        return ReceiptObligationStatus.WAIVED
    if record.payload.status is ObligationStatus.RESOLVED:
        return ReceiptObligationStatus.RESOLVED
    return ReceiptObligationStatus.OPEN


def _select_obligations(
    context: ReceiptBuildContext,
    findings: tuple[Finding, ...],
) -> tuple[ReceiptObligation, ...]:
    plan_scope = current_plan_scope(
        context.projection.plans,
        context.projection.coverage_gaps,
    )
    selected = set(plan_scope.effective_obligation_refs or ())
    for finding in findings:
        selected.update(
            cast(ObligationId, ref) for ref in finding.subject_refs if ref.startswith("obl_")
        )
    obligations: list[ReceiptObligation] = []
    for obligation_id_value in _sorted_unique(selected):
        record = context.projection.obligations.get(obligation_id_value)
        if record is None or record.payload is None:
            continue
        claim_roots: set[ClaimId] = set()
        for claim_id_value, claim_record in effective_claim_items(context.projection):
            if (
                claim_record.payload is not None
                and obligation_id_value in claim_record.payload.obligation_refs
            ):
                claim_roots.add(claim_id_value)
        for finding in findings:
            if obligation_id_value in finding.subject_refs:
                claim_roots.update(
                    cast(ClaimId, ref) for ref in finding.subject_refs if ref.startswith("clm_")
                )
        source_refs = _sorted_unique((*record.payload.source_refs, *claim_roots))
        obligations.append(
            ReceiptObligation(
                obligation_id=obligation_id_value,
                status=_receipt_obligation_status(record),
                source_refs=source_refs,
                summary=record.payload.description,
            )
        )
    return tuple(obligations)


def _select_claim_refs(
    context: ReceiptBuildContext,
    findings: tuple[Finding, ...],
) -> tuple[ClaimId, ...]:
    refs: set[ClaimId] = {
        claim_id_value
        for claim_id_value, record in effective_claim_items(context.projection)
        if record.payload is not None and record.payload.claim_kind is ClaimKind.COMPLETION
    }
    for finding in findings:
        refs.update(cast(ClaimId, ref) for ref in finding.subject_refs if ref.startswith("clm_"))
    for gap in context.gaps:
        refs.update(cast(ClaimId, ref) for ref in gap.subject_refs if ref.startswith("clm_"))
    return _sorted_unique(refs)


def _evidence_from_result(
    projection: ProjectionState,
    result_id_value: ResultId,
) -> set[EvidenceId]:
    record = projection.results.get(result_id_value)
    if record is None or record.payload is None:
        return set()
    return set(record.payload.evidence_refs)


def _select_evidence_refs(
    context: ReceiptBuildContext,
    claims: tuple[ClaimId, ...],
    obligations: tuple[ReceiptObligation, ...],
    responses: tuple[ReceiptResponse, ...],
) -> tuple[EvidenceId, ...]:
    refs: set[EvidenceId] = set()
    for claim_id_value in claims:
        record = context.projection.claims.get(claim_id_value)
        if record is None or record.payload is None:
            continue
        for supporting_ref in record.payload.supporting_refs:
            if supporting_ref.startswith("evd_"):
                refs.add(cast(EvidenceId, supporting_ref))
            elif supporting_ref.startswith("res_"):
                refs.update(
                    _evidence_from_result(context.projection, cast(ResultId, supporting_ref))
                )
            elif supporting_ref.startswith("obl_"):
                obligation_record = context.projection.obligations.get(
                    cast(ObligationId, supporting_ref)
                )
                if obligation_record is not None and obligation_record.payload is not None:
                    for resolution_ref in obligation_record.payload.resolution_evidence_refs:
                        if resolution_ref.startswith("evd_"):
                            refs.add(cast(EvidenceId, resolution_ref))
                        else:
                            refs.update(
                                _evidence_from_result(
                                    context.projection, cast(ResultId, resolution_ref)
                                )
                            )
        if type(record.payload) is ClaimRecordedPayloadV1_1:
            for limitation_ref in record.payload.limitation_refs:
                refs.update(_evidence_from_result(context.projection, limitation_ref))
    for obligation in obligations:
        record = context.projection.obligations.get(obligation.obligation_id)
        if record is None or record.payload is None:
            continue
        for resolution_ref in record.payload.resolution_evidence_refs:
            if resolution_ref.startswith("evd_"):
                refs.add(cast(EvidenceId, resolution_ref))
            else:
                refs.update(
                    _evidence_from_result(context.projection, cast(ResultId, resolution_ref))
                )
    for response in responses:
        for ref in response.evidence_refs:
            if ref.startswith("evd_"):
                refs.add(cast(EvidenceId, ref))
            else:
                refs.update(_evidence_from_result(context.projection, cast(ResultId, ref)))
    for gap in context.gaps:
        for root in gap.subject_refs:
            if not root.startswith("evt_"):
                continue
            refs.update(
                evidence_id_value
                for evidence_id_value, record in context.projection.evidence.items()
                if record.source_event_id == root
            )
    return _sorted_unique(refs)


def _select_responses(
    context: ReceiptBuildContext,
    finding_ids: frozenset[FindingId],
) -> tuple[ReceiptResponse, ...]:
    values: list[ReceiptResponse] = []
    for finding_id_value in sorted(finding_ids, key=_ascii_key):
        record = context.projection.responses.get(finding_id_value)
        if record is None or record.payload is None:
            continue
        payload = record.payload
        values.append(
            ReceiptResponse(
                finding_id=payload.finding_id,
                finding_frontier=payload.finding_frontier,
                disposition=payload.disposition,
                evidence_refs=payload.evidence_refs,
                reason=payload.reason,
                waiver_scope=payload.waiver_scope,
                waiver_expiry=payload.waiver_expiry,
            )
        )
    return tuple(values)


_UNVERIFIED_RESOLUTION_LISTED: Final = 16


# One receipt asks for the lineage once per gap code per rendering; derive it once per context.
_LINEAGE_MEMO: list[tuple[ReceiptBuildContext, tuple[FactLineage, ...]] | None] = [None]


def _receipt_fact_lineage(context: ReceiptBuildContext) -> tuple[FactLineage, ...]:
    """Where the derived facts this receipt reports came from (ADR-045).

    The same list status shows (``current_fact_lineage``): the applicable check's recorded
    deliverable states and the ledger-derived facts of the receipt's prefix. Nothing is claimed
    for a check that no longer applies.
    """

    memo = _LINEAGE_MEMO[0]
    if memo is not None and memo[0] is context:
        return memo[1]
    derived = _derive_receipt_fact_lineage(context)
    _LINEAGE_MEMO[0] = (context, derived)
    return derived


def _derive_receipt_fact_lineage(context: ReceiptBuildContext) -> tuple[FactLineage, ...]:
    items: list[FactLineage] = []
    check = context.applicable_check
    if check is not None:
        event = next(
            (record.event_id for record in context.records if record.payload is check), None
        )
        items.extend(
            deliverable_lineage(event, check.subject_frontier.sequence, check.deliverable_states)
        )
    if context.records and len(context.records) == context.projection.frontier:
        items.extend(task_fact_signals(context.projection, context.records).lineage)
    return tuple(sorted(dict.fromkeys(items), key=lambda item: item.sort_key))


def _check_change_gap_text(
    context: ReceiptBuildContext, code: str, *, name_paths: bool = True
) -> str | None:
    """The fixed sentence for a check-time code; for the legacy-resolution disclosure (R945-02),
    also the affected resolved findings, at most 16 by id and the rest as a count. A task fact
    that carries provenance (ADR-045) also says why it fired, from the same lineage status
    shows. ``name_paths=False`` counts the undeclared files instead of naming them: their paths
    are repository-excerpt content only ``full_local`` carries."""

    later = _later_material_text(context, code)
    if later is not None:
        return later
    sentence = check_time_change_gap_sentence(code)
    if sentence is not None and code == DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP:
        # tb4n4 (#1044): name the undeclared files from the applicable check's recorded
        # deliverable states, with the same sentence the Stop gate prints.
        check = context.applicable_check
        rows = undeclared_reference_rows(check.deliverable_states) if check is not None else ()
        if not name_paths:
            rows = tuple((obligation, index, (), total) for obligation, index, _, total in rows)
        named = undeclared_reference_variants(rows)
        return f"{sentence} {named[0]}" if named else sentence
    if sentence is not None and code == DELIVERABLE_REFERENCES_AMBIGUOUS_NAME_GAP:
        # tb4n5 (ADR-035 amendment): how many, never which; the bound the heuristic left open.
        check = context.applicable_check
        count = ambiguous_reference_count(check.deliverable_states) if check is not None else 0
        return f"{sentence} Files named ambiguously: {count}." if count else sentence
    if sentence is not None and code != CHECK_TIME_CHANGE_RESOLUTION_UNVERIFIED_GAP:
        why = lineage_texts(_receipt_fact_lineage(context), code)
        if why:
            shown = " ".join(why[:3])
            return f"{sentence} {shown}" + (f" (+{len(why) - 3} more.)" if len(why) > 3 else "")
    if sentence is None or code != CHECK_TIME_CHANGE_RESOLUTION_UNVERIFIED_GAP:
        return sentence
    affected = unverified_resolution_finding_ids(
        context.projection,
        (state.finding_id for state in context.finding_states if state.resolved),
    )
    if not affected:
        return sentence
    listed = ", ".join(str(item) for item in affected[:_UNVERIFIED_RESOLUTION_LISTED])
    remaining = len(affected) - _UNVERIFIED_RESOLUTION_LISTED
    more = f", and {remaining} more" if remaining > 0 else ""
    noun = "finding" if len(affected) == 1 else "findings"
    return f"{sentence} {len(affected)} resolved AI-powered {noun} rely on it: {listed}{more}."


_LATER_CLASS_PHRASES: Final[Mapping[LaterMaterialClass, str]] = MappingProxyType(
    {
        LaterMaterialClass.FINISHUP_OWN_CALL: "records of FinishUP's own tool calls",
        LaterMaterialClass.EXPLORATION: "records of read-only reads",
        LaterMaterialClass.NO_TOOL_ACTIVITY: "host bookkeeping records that name no tool call",
        LaterMaterialClass.NON_COUNTING_WRITE: "records of scratch or FinishUP-owned writes",
    }
)


def _later_record_phrase(record: LaterRecord) -> str:
    """Name one later record in the reader's terms: what it is, its ledger position, its id."""

    where = f"ledger record {record.ingestion_sequence}, {record.event_id}"
    tool = "" if record.material.tool is None else f" via {record.material.tool}"
    if record.material.material_class is LaterMaterialClass.EDIT_OR_WRITE:
        return f"an observed edit{tool} ({where})"
    if record.family == "finding_recorded" and record.observation_authored:
        return f"a host-observation finding ({where})"
    if record.observation_authored:
        return f"an unclassified host observation, {record.family}{tool} ({where})"
    return f"published {record.family} work ({where})"


def _later_material_text(context: ReceiptBuildContext, code: str) -> str | None:
    """Why the check no longer covers this frontier, or why the earlier-frontier code bounds.

    Every fact the receipt adds says which record it rests on, the closed rule that classified it
    and the check frontier it follows (tb4n3 RC-6; the owner's lineage rule). ``None`` for any
    other code, or when the application passed no standing (a hand-built context).
    """

    standing = context.check_standing
    latest = None if standing is None else standing.latest
    if standing is None or latest is None:
        return None
    tested = f"subject frontier {latest.subject_frontier.sequence}"
    if code == "check_not_applicable":
        cause = standing.superseded_by
        if cause is None:
            return None
        sentence = (
            f"Why: {_later_record_phrase(cause)} was recorded after the check at {tested} "
            f"(rule {cause.material.rule})."
        )
        if cause.material.material_class is LaterMaterialClass.EDIT_OR_WRITE:
            sentence += (
                " The host hook records the tool and whether the write left the workspace, not "
                "the path; the next check reads the changed files."
            )
        return sentence
    if code == CHECK_CURRENT_AS_OF_EARLIER_FRONTIER_GAP:
        first = standing.bounding_first or standing.counted_first
        if standing.superseded_by is not None or first is None:
            return None
        answers = sum(1 for record in standing.counted if not is_observation_authored(record))
        unclassified = len(standing.counted) - answers
        parts: list[str] = []
        if unclassified:
            parts.append(
                f"{_count_phrase(unclassified, 'later record', 'later records')} could not be "
                "classified as FinishUP's own calls, read-only reads, host bookkeeping or "
                "scratch writes"
            )
        if answers:
            parts.append(
                f"{_count_phrase(answers, 'later response', 'later responses')} answered findings"
            )
        sentence = (
            f"Why: after the check at {tested}, " + " and ".join(parts) + "; the first is "
            f"{_later_record_phrase(first)} (rule {first.material.rule})."
        )
        if standing.ignored:
            ignored = ", ".join(
                f"{count} {_LATER_CLASS_PHRASES.get(kind, kind.value)}"
                for kind, count in standing.ignored.items()
            )
            sentence += f" Not counted, because FinishUP classified them as not changing the work: {ignored}."
        return sentence
    return None


def _select_gaps(
    context: ReceiptBuildContext,
    historical: Mapping[str, Frontier] | None = None,
    effects: Mapping[str, ReceiptGapEffect] | None = None,
) -> tuple[ReceiptGap, ...]:
    cleared = historical or {}
    plan_scope = current_plan_scope(
        context.projection.plans,
        context.projection.coverage_gaps,
    )
    differences = completion_scope_differences(context.projection)

    def scope_detail(code: str) -> str | None:
        if code not in {COMPLETION_CLAIM_OUTSIDE_PLAN_GAP, COMPLETION_PLAN_NOT_CLAIMED_GAP}:
            return None
        pairs = [
            (row.claim_id, refs)
            for row in differences
            if (
                refs := (
                    row.outside_plan
                    if code == COMPLETION_CLAIM_OUTSIDE_PLAN_GAP
                    else row.not_claimed
                )
            )
        ]
        # The gap code can be retained from a frozen check while the current projection has
        # already repaired the relation. Do not render a contradictory zero-count detail.
        if not pairs:
            return None
        count = sum(len(refs) for _, refs in pairs)
        previews = [f"{claim}: {ref}" for claim, refs in pairs for ref in refs][:16]
        relation_text = "; ".join(previews)
        if count > 16:
            relation_text += "; additional relations omitted"
        return (
            f"{len(pairs)} completion claim(s), {count} obligation relation(s)."
            + (f" {relation_text}." if relation_text else "")
            + f" {SCOPE_REPAIR}"
        )

    values = tuple(
        ReceiptGap(
            code=gap.code,
            subject_refs=gap.subject_refs,
            detail=(
                plan_scope.no_obligations_reason.value
                if gap.code == COMPLETION_SCOPE_DECLARED_NONE_GAP
                and plan_scope.no_obligations_reason is not None
                else scope_detail(gap.code)
                or task_statement_gap_detail(gap.code)
                or _check_change_gap_text(context, gap.code)
            ),
            status=(ReceiptGapStatus.HISTORICAL if gap.code in cleared else ReceiptGapStatus.LIVE),
            cleared_at_frontier=cleared.get(gap.code),
            effect=(None if effects is None or gap.code in cleared else effects.get(gap.code)),
        )
        for gap in sorted(
            context.gaps,
            key=lambda gap: (
                _ascii_key(gap.code),
                tuple(_ascii_key(ref) for ref in gap.subject_refs),
                _ascii_key(gap.marker),
            ),
        )
    )
    return values


def _redacted_event_category(
    projection: ProjectionState,
    source_event_id: EventId,
) -> ReceiptRedactionCategory:
    family_categories: tuple[
        tuple[Iterable[ProjectionRecord[object]], ReceiptRedactionCategory], ...
    ] = (
        (
            cast(Iterable[ProjectionRecord[object]], projection.claims.values()),
            ReceiptRedactionCategory.CLAIM_TEXT,
        ),
        (
            cast(Iterable[ProjectionRecord[object]], projection.findings.values()),
            ReceiptRedactionCategory.FINDING_DETAIL,
        ),
        (
            cast(Iterable[ProjectionRecord[object]], projection.responses.values()),
            ReceiptRedactionCategory.FINDING_DETAIL,
        ),
        (
            cast(Iterable[ProjectionRecord[object]], projection.obligations.values()),
            ReceiptRedactionCategory.OBLIGATION_TEXT,
        ),
        (
            cast(Iterable[ProjectionRecord[object]], projection.evidence.values()),
            ReceiptRedactionCategory.EVIDENCE_CONTENT,
        ),
    )
    for records, category in family_categories:
        if any(record.source_event_id == source_event_id for record in records):
            return category
    return ReceiptRedactionCategory.REPOSITORY_CONTENT


def _source_redaction_counts(
    context: ReceiptBuildContext,
) -> Counter[tuple[ReceiptRedactionCategory, ReceiptRedactionReason]]:
    counts: Counter[tuple[ReceiptRedactionCategory, ReceiptRedactionReason]] = Counter()
    redacted_objects: set[str] = set()
    redacted_events: set[EventId] = set()
    for gap in context.gaps:
        if gap.marker.startswith("redacted_object:"):
            redacted_objects.add(gap.marker.removeprefix("redacted_object:"))
        elif gap.marker.startswith("redacted_event:"):
            redacted_events.add(cast(EventId, gap.marker.removeprefix("redacted_event:")))
    if redacted_objects:
        counts[
            (ReceiptRedactionCategory.EVIDENCE_CONTENT, ReceiptRedactionReason.SOURCE_REDACTED)
        ] += len(redacted_objects)
    for source_event_id in redacted_events:
        category = _redacted_event_category(context.projection, source_event_id)
        counts[(category, ReceiptRedactionReason.SOURCE_REDACTED)] += 1
    return counts


def _apply_profile(
    context: ReceiptBuildContext,
    profile: ReceiptRedactionProfile,
    findings: tuple[Finding, ...],
    obligations: tuple[ReceiptObligation, ...],
    responses: tuple[ReceiptResponse, ...],
    gaps: tuple[ReceiptGap, ...],
) -> tuple[
    tuple[Finding, ...],
    tuple[ReceiptObligation, ...],
    tuple[ReceiptResponse, ...],
    tuple[ReceiptGap, ...],
    tuple[ReceiptRedaction, ...],
]:
    counts = _source_redaction_counts(context)
    retained_findings = findings
    retained_obligations = obligations
    retained_responses = responses
    retained_gaps = gaps

    if profile in {
        ReceiptRedactionProfile.DEFAULT_LOCAL_EXPORT,
        ReceiptRedactionProfile.REDACTED_SHARE,
    }:
        if _reviewer_advisory_text(context.applicable_check) is not None:
            # #1118: the reviewer's summary is withheld from export views, with an explicit item.
            counts[
                (ReceiptRedactionCategory.FINDING_DETAIL, ReceiptRedactionReason.POLICY_REDACTED)
            ] += 1
        cleared = sum(obligation.summary is not None for obligation in obligations)
        if cleared:
            counts[
                (ReceiptRedactionCategory.OBLIGATION_TEXT, ReceiptRedactionReason.POLICY_REDACTED)
            ] += cleared
        retained_obligations = tuple(
            replace(obligation, summary=None) for obligation in obligations
        )

        def retain_closed_scope_reason(gap: ReceiptGap) -> bool:
            if gap.code != COMPLETION_SCOPE_DECLARED_NONE_GAP or gap.detail is None:
                return False
            try:
                NoObligationsReason(gap.detail)
            except ValueError:
                return False
            return True

        cleared_gaps = sum(
            gap.detail is not None and not retain_closed_scope_reason(gap) for gap in gaps
        )
        if cleared_gaps:
            counts[
                (ReceiptRedactionCategory.FINDING_DETAIL, ReceiptRedactionReason.POLICY_REDACTED)
            ] += cleared_gaps
        retained_gaps = tuple(
            gap if retain_closed_scope_reason(gap) else replace(gap, detail=None) for gap in gaps
        )

    if profile is ReceiptRedactionProfile.REDACTED_SHARE:
        semantic_count = sum(
            finding.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED for finding in findings
        )
        if semantic_count:
            counts[
                (ReceiptRedactionCategory.FINDING_DETAIL, ReceiptRedactionReason.POLICY_REDACTED)
            ] += 2 * semantic_count
        retained_findings = tuple(
            finding for finding in findings if finding.origin is FindingOrigin.DETERMINISTIC
        )
        transformed_responses: list[ReceiptResponse] = []
        for response in responses:
            # A ``duplicate_of`` answer (issue #996) has an optional reason like acknowledged.
            if response.disposition in {
                ResponseDisposition.ACKNOWLEDGED,
                ResponseDisposition.DUPLICATE_OF,
            }:
                if response.reason is not None:
                    counts[
                        (
                            ReceiptRedactionCategory.FINDING_DETAIL,
                            ReceiptRedactionReason.POLICY_REDACTED,
                        )
                    ] += 1
                transformed_responses.append(replace(response, reason=None))
            elif response.disposition in {
                ResponseDisposition.ACKNOWLEDGED_NOT_DONE,
                ResponseDisposition.PROVENANCE_DISPUTED,
                ResponseDisposition.REJECTED,
                ResponseDisposition.SELF_VERIFIED,
                ResponseDisposition.WAIVED,
            }:
                counts[
                    (
                        ReceiptRedactionCategory.FINDING_DETAIL,
                        ReceiptRedactionReason.POLICY_REDACTED,
                    )
                ] += 1
        retained_responses = tuple(transformed_responses)

    rows = tuple(
        ReceiptRedaction(category=category, reason=reason, count=count)
        for (category, reason), count in sorted(
            counts.items(),
            key=lambda item: (_ascii_key(item[0][0].value), _ascii_key(item[0][1].value)),
        )
        if count > 0
    )
    return (
        retained_findings,
        retained_obligations,
        retained_responses,
        retained_gaps,
        rows,
    )


_CHILD_FINDING_CAP: Final = 64


def _child_finding_rank(finding: ReceiptChildFinding) -> int:
    """0 unresolved actionable work, 1 self-verified, 2 other unresolved, 3 resolved history.

    A self-verified child finding is also actionable and unresolved, but it is not the parent's
    work (ADR-034), so a finding that still needs work outranks it.
    """

    if finding.resolved:
        return 3
    if finding.self_verified:
        return 1
    return 0 if finding.actionable else 2


def _receipt_children(evaluation: LineageEvaluation | None) -> tuple[ReceiptChildren, int]:
    """Project the pure lineage evaluation into the receipt's bounded child section.

    Lineage allows 100 findings per child while a receipt child outcome holds 64 (tb4n3 RC-2, A6):
    a child past that used to fail the whole receipt. The rest are counted, not silently dropped.
    """

    if evaluation is None:
        return ReceiptChildren(), 0
    omitted_child_findings = 0
    snapshots = {snapshot.child_task_id: snapshot for snapshot in evaluation.snapshots}
    children: list[ReceiptChildOutcome] = []
    for rollup in evaluation.children:
        snapshot = snapshots.get(rollup.child_task_id)
        if snapshot is None:
            # A synthetic rollup without its source snapshot cannot be rendered as a truthful
            # child finding row.  Keep the child identity and outcome while naming the missing
            # source through the evaluator's coverage gap.
            findings: tuple[ReceiptChildFinding, ...] = ()
        else:
            findings = tuple(
                ReceiptChildFinding(
                    finding_id=finding.finding_id,
                    kind=finding.kind,
                    origin=finding.origin,
                    priority=finding.priority,
                    actionable=bool(finding.actionable),
                    resolved=finding.resolved,
                    resolution_event_id=finding.resolution_event_id,
                    self_verified=finding.self_verified,
                )
                for finding in snapshot.findings
            )
            findings, omitted = _keep_by_rank(findings, _CHILD_FINDING_CAP, _child_finding_rank)
            omitted_child_findings += omitted
        # ``blocked`` is the evaluator's internal state for unresolved actionable child findings;
        # receipts expose the bounded child outcome vocabulary, where that state is an open gap
        # accompanied by the actionable finding rows.
        outcome = (
            "annotated"
            if rollup.state is LineageRollupState.ANNOTATION
            else "open_gap"
            if rollup.state is LineageRollupState.BLOCKED
            else rollup.outcome
        )
        children.append(
            ReceiptChildOutcome(
                child_task_id=rollup.child_task_id,
                outcome=cast(
                    Literal["clean", "annotated", "open_gap", "incomplete", "unavailable"],
                    outcome,
                ),
                tested_manifest_ref=(
                    None
                    if rollup.state is LineageRollupState.UNAVAILABLE
                    else rollup.tested_manifest_ref
                ),
                later_manifest_ref=rollup.later_manifest_ref,
                freshness=cast(Literal["known", "unknown"], rollup.freshness),
                findings=findings,
            )
        )
    return ReceiptChildren(tuple(children)), omitted_child_findings


def route_did_not_require_review(check: CheckRecordedPayload | None) -> bool:
    """True when ``check`` recorded a route that did not require AI-powered review (#986).

    Only an explicit ``semantic_route_required: false`` on a local-only check (``not_requested``)
    qualifies; an absent field is the safe default and keeps the missing review blocking. Since
    #1041 such a check no longer records ``semantic_review_not_requested`` when it asked for no
    review, so the gap itself is not part of the test.
    """

    return (
        check is not None
        and check.semantic_route_required is False
        and check.semantic_status is SemanticStatus.NOT_REQUESTED
    )


def _flag_closure(
    context: ReceiptBuildContext, state: ReceiptFindingState, *, terminal_sections: bool
) -> FindingClosure | None:
    """The closure of a state that carries only the per-state flags (a hand-built context).

    The application always supplies ``closure`` from ``kernel.closure_class``; this mirrors its
    bases for the flags a context can state, so a hand-built context reads the same rules.
    """

    record = context.projection.findings.get(state.finding_id)
    if record is None or record.payload is None:
        return None
    finding = record.payload
    if not FINDING_KIND_TRAITS[finding.kind][1]:
        return None
    if state.resolved:
        basis = (
            (
                "retired_by_planned_verification"
                if record.retired_by_planned_verification
                else "retired_by_passing_run"
            )
            if record.resolved_by_check_event_id is None and record.retired_by_event_id is not None
            else "absence_proved"
        )
    elif state.acknowledged_not_done:
        basis = (
            "acknowledged_not_done_bookkeeping"
            if is_bookkeeping_finding(context.projection, state.finding_id)
            else "acknowledged_not_done_requirement"
        )
    elif state.rejection_accepted:
        basis = "rejection_accepted"
    elif state.self_verified:
        basis = "self_verified"
    elif state.disputed_after_rebuttal:
        basis = "disputed_after_rebuttal"
    else:
        basis = "open_answered"
    if not terminal_sections and basis in {
        "rejection_accepted",
        "self_verified",
        "disputed_after_rebuttal",
    }:
        # An artifact older than the terminal sections cannot disclose these by id, so they still
        # block there (issue #905): read them as open work.
        basis = "open_answered"
    klass, effect = FINDING_BASES[basis]
    return FindingClosure(
        state.finding_id,
        klass,
        basis,
        effect,
        ("none",),
        None,
        (),
        state.duplicate_of_finding_id or state.finding_id,
    )


def _context_closures(
    context: ReceiptBuildContext, *, terminal_sections: bool
) -> tuple[FindingClosure, ...]:
    closures: list[FindingClosure] = []
    for state in context.finding_states:
        closure = state.closure
        if closure is None:
            closure = _flag_closure(context, state, terminal_sections=terminal_sections)
        elif not terminal_sections and closure.basis in {
            "rejection_accepted",
            "self_verified",
            "disputed_after_rebuttal",
        }:
            closure = _flag_closure(context, state, terminal_sections=False)
        if closure is not None:
            closures.append(closure)
    return tuple(closures)


def _gap_context(context: ReceiptBuildContext, historical: frozenset[str]) -> GapContext:
    """What the applicable check and the suffix say about each gap (one computation).

    The route comes from the check's own record (only an explicit ``semantic_route_required:
    false`` on a local-only check relaxes anything, issue #986); the host-observation guard from
    the gaps that check carried; the earlier-frontier bound from the suffix that followed it.
    """

    check = context.applicable_check
    carried: frozenset[str] = (
        frozenset(check.coverage.known_gaps) if check is not None else frozenset[str]()
    )
    if context.check_suffix is not None:
        bounds = context.check_suffix is not CheckSuffixClass.RESPONSES_ONLY
    elif context.check_standing is not None:
        bounds = context.check_standing.bounds_conclusion
    else:
        bounds = True
    return GapContext(
        route_requires_review=not route_did_not_require_review(check),
        review_succeeded=check is not None and check.semantic_status is SemanticStatus.SUCCEEDED,
        reviewer_reported_insufficiency=bool(
            carried
            & {
                "semantic_packet_insufficient",
                SEMANTIC_REVIEW_SKIPPED_INSUFFICIENT_PACKET_GAP,
            }
            or any(code.startswith("semantic_missing_") for code in carried)
        ),
        check_carried=carried,
        commands_complete=(
            True if check is None or check.totals is None else commands_complete(check.totals)
        ),
        earlier_frontier_bounds=bounds,
        historical=historical,
        # #1143: the route the applicable check judged freshness on: its recorded route required
        # review, or a review was used before it (``freshness_review_used``).
        freshness_advisory=(check is not None and check.semantic_route_required is None)
        or freshness_review_used(context.records),
    )


def _applied_check(check: CheckRecordedPayload | None) -> AppliedCheck | None:
    if check is None:
        return None
    # A pack that ran to completion, or that had nothing to judge on the whole case
    # (``skipped/not_applicable``: no root of its kind exists, e.g. the coordination pack on a
    # single-agent run), leaves nothing unexamined (#986). ``scope_excluded`` (a scoped check
    # left roots of the pack unexamined) and ``material_unavailable`` (its roots were
    # unreadable) are real coverage loss and stay incomplete, as does ``failed``.
    complete = all(
        (execution.outcome == "run" and execution.reason == "completed")
        or (execution.outcome == "skipped" and execution.reason == "not_applicable")
        for execution in check.policy_executions
    )
    return AppliedCheck(check.verdict, check.suppressed_count, complete)


def closure_basis_from_context(
    context: ReceiptBuildContext,
    *,
    terminal_sections: bool = True,
    obligations: tuple[ObligationClosure, ...] | None = None,
) -> ClosureBasis:
    """The basis the receipt conclusion reads, built from one frozen receipt context.

    ``terminal_sections`` is false only for an artifact older than the terminal-state sections
    (``receipt_document_carries_terminal_sections``), which cannot disclose a settled finding by
    id and so keeps it blocking. Status builds the same context and calls the same function, so
    the label it prints is the label the receipt carries.
    """

    historical: frozenset[str] = (
        frozenset(code for code, _ in context.historical_gaps)
        if terminal_sections
        else frozenset[str]()
    )
    live = set(context.coverage.known_gaps) - historical
    if unresolved_verification_obligations(context.projection, context.records):
        live.add(UNRESOLVED_VERIFICATION_GAP)
    live_codes = tuple(sorted(live, key=_ascii_key))
    gap_context = _gap_context(context, historical)
    gaps = judge_gaps(live_codes, gap_context)
    if context.applicable_check is None:
        # No check covers the state, so the missing check is the reason; its own gap is a symptom.
        gaps = tuple(gap for gap in gaps if gap.code not in _CHECK_ABSENCE_GAPS)
    lineage = context.lineage
    return ClosureBasis(
        context.subject_frontier,
        _context_closures(context, terminal_sections=terminal_sections),
        tuple(obligation_closures(context.projection, records=context.records).values())
        if obligations is None
        else obligations,
        gaps,
        _applied_check(context.applicable_check),
        None
        if lineage is None
        else LineageBasis(
            tuple(str(item) for item in lineage.actionable_finding_ids),
            lineage.blocks_clean_completion,
        ),
    )


def predict_context_conclusion(
    context: ReceiptBuildContext, *, terminal_sections: bool = True
) -> ReceiptPrediction:
    """The prediction (conclusion and every reason) for one receipt context."""

    return predict_receipt_conclusion(
        closure_basis_from_context(context, terminal_sections=terminal_sections)
    )


def _count_phrase(count: int, singular: str, plural: str) -> str:
    if count == 0:
        return f"no {plural}"
    if count == 1:
        return f"one {singular}"
    return f"{count} {plural}"


def _resolved_history_sentence(
    resolved_count: int, retired_count: int = 0, planned_count: int = 0
) -> str:
    """Name resolved historical findings apart from current ones and from coverage gaps.

    A resolved finding is not erased and is not a limitation: it fired, the record was repaired,
    and a later qualifying check found the same issue absent. Saying so beside the current count
    is what lets a reader tell "was fixed" from "still open" without a per-finding flag, which the
    frozen receipt document does not carry. ``retired_count`` of them were observed failed-command
    findings a later passing run of the same command retired (#1104), and ``planned_count`` of
    them a later passing planned verification retired (owner decision 2026-10-18); each kind is
    named on its own so the receipt never says a check proved what only a rerun did, nor that the
    failed command itself passed when only the planned verification did.
    """

    checked = resolved_count - retired_count - planned_count
    sentence = ""
    if checked > 0:
        phrase = _count_phrase(checked, "earlier finding was", "earlier findings were")
        sentence += (
            f" {phrase[:1].upper() + phrase[1:]} resolved by a later qualifying check and "
            + ("remain" if checked > 1 else "remains")
            + " visible as history."
        )
    if retired_count > 0:
        phrase = _count_phrase(
            retired_count,
            "earlier failed-command finding was",
            "earlier failed-command findings were",
        )
        sentence += (
            f" {phrase[:1].upper() + phrase[1:]} retired by a later passing run of the same "
            "command and " + ("remain" if retired_count > 1 else "remains") + " visible as history."
        )
    if planned_count > 0:
        phrase = _count_phrase(
            planned_count,
            "earlier failed-command finding was",
            "earlier failed-command findings were",
        )
        sentence += (
            f" {phrase[:1].upper() + phrase[1:]} retired by a later passing run of a planned "
            "verification, not of the command that failed, and "
            + ("remain" if planned_count > 1 else "remains")
            + " visible as history."
        )
    return sentence


def _retired_count(
    projection: ProjectionState, finding_ids: tuple[FindingId, ...], *, planned: bool
) -> int:
    """How many of *finding_ids* a later passing run retired (#1104), of one kind."""

    return sum(
        1
        for item in finding_ids
        if (record := projection.findings.get(item)) is not None
        and record.resolved_by_check_event_id is None
        and record.retired_by_event_id is not None
        and record.retired_by_planned_verification is planned
    )


def _failed_command_trigger(projection: ProjectionState, key: FindingId) -> str:
    """Keep the original trigger visible beside the current resolution basis (#1160)."""

    record = projection.findings.get(key)
    if not is_observed_failed_command_finding(record) or record is None:
        return ""
    result = (
        projection.results.get(record.failed_run_result_id) if record.failed_run_result_id else None
    )
    if result is None or result.payload is None:
        return ""
    action = projection.actions.get(result.payload.action_id)
    if action is None or action.payload is None:
        return ""
    return (
        f" Original failed-command trigger: {action.source_event_id} / {result.source_event_id};"
        f" finding first recorded at frontier {record.source_frontier}."
    )


_OBSERVED_HISTORY_LISTED: Final = 10


def _listed_refs(refs: set[ResultId]) -> str:
    ordered = sorted(refs, key=_ascii_key)
    listed = ", ".join(ordered[:_OBSERVED_HISTORY_LISTED])
    extra = len(ordered) - _OBSERVED_HISTORY_LISTED
    return f"{listed} and {extra} more" if extra > 0 else listed


def _observed_failure_history_sentence(context: ReceiptBuildContext) -> str:
    """Disclose, once, the hook-observed failures a completion claim did not have to name (#909).

    A failure a later run of the same command superseded is not a finding, but it is never silent:
    the receipt counts and names it here, beside the observed failures the claim disclosed through
    ``limitation_refs``. Legacy historical rows remain readable for replay; current edits do not
    create history because they prove no covering rerun.
    """

    if not context.records:
        return ""
    observed = observed_event_ids_from_records(context.records)
    if not observed:
        return ""
    superseded: set[ResultId] = set()
    rerun: set[ResultId] = set()
    historical: set[ResultId] = set()
    disclosed: set[ResultId] = set()
    for _claim_id, claim_record in effective_claim_items(context.projection):
        claim = claim_record.payload
        if claim is None or claim.claim_kind is not ClaimKind.COMPLETION:
            continue
        states = observed_failure_states(
            context.projection, observed, through=claim_record.source_frontier
        )
        for ref, state in states.items():
            if not result_is_relevant_to_claim(context.projection, claim_record, ref):
                continue
            if claim_discloses_result(claim, ref):
                disclosed.add(ref)
            elif state is ObservedFailureState.SUPERSEDED:
                superseded.add(ref)
            elif state is ObservedFailureState.RERUN:
                rerun.add(ref)
            elif state is ObservedFailureState.HISTORICAL:
                historical.add(ref)
    superseded -= disclosed
    rerun -= disclosed | superseded
    historical -= disclosed | superseded | rerun
    parts: list[str] = []
    if superseded or rerun or historical:
        clauses: list[str] = []
        if superseded:
            verb = "was" if len(superseded) == 1 else "were"
            clauses.append(
                f"{len(superseded)} {verb} later passed by the same command "
                f"({_listed_refs(superseded)})"
            )
        if rerun:
            verb = "was" if len(rerun) == 1 else "were"
            clauses.append(
                f"{len(rerun)} {verb} rerun later by the same command, whose latest run is "
                f"judged instead ({_listed_refs(rerun)})"
            )
        if historical:
            clauses.append(
                f"{len(historical)} preceded a later observed workspace edit "
                f"({_listed_refs(historical)})"
            )
        total = len(superseded) + len(rerun) + len(historical)
        noun = "run" if total == 1 else "runs"
        parts.append(
            f"Observed failure history: of the hook-observed failing {noun} before the "
            f"completion claim, {', '.join(clauses[:-1]) + ' and ' if len(clauses) > 1 else ''}"
            f"{clauses[-1]}. "
            f"{'It is' if total == 1 else 'They are'} recorded history, not findings."
        )
    if disclosed:
        disclosure = (
            "run is disclosed as a limitation"
            if len(disclosed) == 1
            else "runs are disclosed as limitations"
        )
        parts.append(
            f"{len(disclosed)} hook-observed failing {disclosure} by the completion claim "
            f"({_listed_refs(disclosed)})."
        )
    return " ".join(parts)


@dataclass(frozen=True, slots=True)
class _CallerDigestCounts:
    """Distinct cited evidence items per caller-digest retention semantic (issue #912).

    ``digest_only`` and ``withheld`` mean different things for what the owner can recover: a
    digest-only record kept the digest but never retained the bytes, while a withheld record
    records that the publisher withheld them. The receipt keeps the two apart.
    """

    digest_only: int = 0
    withheld: int = 0

    @property
    def total(self) -> int:
        return self.digest_only + self.withheld


_NO_CALLER_DIGESTS: Final = _CallerDigestCounts()


def _caller_digest_counts(context: ReceiptBuildContext) -> _CallerDigestCounts:
    """Count cited evidence items whose caller-asserted digest FinishUP did not verify.

    The case records one per-item gap, rooted at the evidence's source event, for each cited
    ``digest_only`` or ``withheld`` binding; one evidence record carries exactly one availability,
    so the two counts never share an item. A code carried only by check coverage or a retained
    finding has no per-item root and is named without a count.
    """

    def distinct(code: str) -> int:
        return len(
            {gap.subject_refs for gap in context.gaps if gap.code == code and gap.subject_refs}
        )

    return _CallerDigestCounts(
        digest_only=distinct("evidence_content_digest_only"),
        withheld=distinct("evidence_content_withheld"),
    )


def _caller_digest_retention_clause(counts: _CallerDigestCounts) -> str:
    """Say what was retained for the counted items without merging the two retention facts."""

    digest_only = "the digest was recorded but the bytes were not retained"
    withheld = "the publisher recorded the bytes as withheld"
    if counts.withheld == 0:
        return digest_only
    if counts.digest_only == 0:
        return withheld
    only_verb = "is" if counts.digest_only == 1 else "are"
    withheld_verb = "is" if counts.withheld == 1 else "are"
    return (
        f"{counts.digest_only} {only_verb} digest-only ({digest_only}) and "
        f"{counts.withheld} {withheld_verb} withheld ({withheld})"
    )


def _caller_digest_sentence(counts: _CallerDigestCounts) -> str:
    """Name the caller-asserted digest provenance limitation once, with a count (issue #912).

    This is the fallback provenance label: an unverified caller digest raises no finding, yet
    the receipt must still say that FinishUP did not verify those bytes. The retention clause keeps
    digest-only items (bytes never retained) apart from withheld items (the publisher withheld
    the bytes), because the two differ in what the owner can recover. Nothing an agent publishes
    changes the recorded provenance, so the sentence names no remedy. Without a per-item root the
    code comes only from recorded check or finding coverage; the sentence then describes that
    recorded limitation instead of implying currently cited items, and makes no permanence claim
    because a later check of the current record may no longer carry it.
    """

    if counts.total == 0:
        return (
            "Recorded check or finding coverage names caller-asserted digests that FinishUP did not "
            "verify; no currently cited evidence item carries one."
        )
    if counts.total == 1:
        subject = "One cited evidence item carries a caller-asserted digest"
    else:
        subject = f"{counts.total} cited evidence items carry caller-asserted digests"
    return (
        f"{subject} that FinishUP did not verify: {_caller_digest_retention_clause(counts)}. "
        "This provenance limitation stays disclosed here and no response or recheck changes it."
    )


def _suffix_record_kinds(context: ReceiptBuildContext) -> tuple[str | None, bool, bool]:
    """Return whether an attributable suffix contains service lineage, host observations, and
    acknowledgements of observation-authored limitations the check did not return.

    ``CheckSuffixClass`` is intentionally derived by the application and remains the public
    render context.  The builder has the frozen records as well, so it can refine the prose for
    a service-generated lineage manifest without changing that context enum or any receipt wire
    shape.  This is strictly a read over the recorded prefix; it never refreshes child state.
    The applicability rule already proved that a readable response in the suffix answers either a
    returned finding or an observation-authored limitation (issue #911), so a response naming a
    finding outside the returned set is exactly the latter.
    """

    if (
        context.check_suffix is None
        or context.applicable_check is None
        or not context.records
        or context.projection.latest_tested_state is None
    ):
        return None, False, False
    latest = context.projection.latest_tested_state
    check_event_id = latest.source_check_event_id
    check_record = next(
        (record for record in context.records if record.event_id == check_event_id),
        None,
    )
    if check_record is None:
        return None, False, False
    # The same filter the application used to derive ``check_suffix`` (tb4n3 RC-6): records the
    # shared ``later_material_class`` rule proves harmless are not part of the disclosed suffix.
    later_material = (
        context.check_standing.counted
        if context.check_standing is not None
        else counted_later_material(
            (
                record
                for record in context.records
                if is_material_event_family(record.schema.name)
                and record.ledger.ingestion_sequence > check_record.ledger.ingestion_sequence
            ),
            context.projection,
            all_records=context.records,
        )
    )
    lineage_records = tuple(
        record for record in later_material if is_lineage_service_stamped(record)
    )
    lineage_label: str | None = None
    if lineage_records:
        lineage_label = (
            "service-generated child-dependency manifests"
            if all(
                record.schema.name == "child_dependencies_recorded" for record in lineage_records
            )
            else "service-generated lineage records"
        )
    return (
        lineage_label,
        any(
            is_observation_authored(record) and not is_lineage_service_stamped(record)
            for record in later_material
        ),
        any(
            record.schema.name == "response_recorded"
            and type(record.payload) is ResponseRecordedPayload
            and record.payload.finding_id not in latest.returned_finding_ids
            for record in later_material
        ),
    )


def _check_coverage_sentence(
    gap_codes: tuple[str, ...],
    frontier: Frontier,
    tested_subject_sequence: str | None,
    check_suffix: CheckSuffixClass | None = None,
    *,
    engine_derived_suffix: str | None = None,
    host_observation_suffix: bool = False,
    limitation_response_suffix: bool = False,
    superseded_by_observation: bool = False,
) -> str:
    """State what the recorded check does or does not cover here, in the reader's terms."""

    if CHECK_CURRENT_AS_OF_EARLIER_FRONTIER_GAP in gap_codes:
        tested = (
            "an earlier subject frontier"
            if tested_subject_sequence is None
            else f"subject frontier {tested_subject_sequence}"
        )
        # The gap means "an attributable earlier check", not "a response-only suffix": the
        # authorship-aware applicability rule also keeps a check across finding-free host
        # observations (issue #657). Name the suffix class the application established, and fall
        # back to neutral wording rather than inventing an event class it did not establish.
        # Acknowledging an observation-authored limitation the check never returned also keeps it
        # attributable (issue #911); name that too rather than implying every response answered
        # the check's own findings.
        responses = "responses to the findings it returned" + (
            " or to observation-authored coverage limitations" if limitation_response_suffix else ""
        )
        if check_suffix is CheckSuffixClass.RESPONSES_ONLY:
            later = f"only {responses} were published after it"
        elif check_suffix is CheckSuffixClass.OBSERVATIONS_ONLY:
            if engine_derived_suffix is not None:
                later = (
                    f"the records accepted after it through frontier {frontier.sequence} are "
                    + (
                        "finding-free host observations and "
                        f"{engine_derived_suffix}, retained here but not evaluated by that check"
                        if host_observation_suffix
                        else f"{engine_derived_suffix}, retained here but not evaluated by that check"
                    )
                )
            else:
                later = (
                    f"the records accepted after it through frontier {frontier.sequence} are "
                    "finding-free host observations, retained here but not evaluated by that check"
                )
        elif check_suffix is CheckSuffixClass.MIXED:
            if engine_derived_suffix is not None:
                later = (
                    f"the records accepted after it through frontier {frontier.sequence} are "
                    f"{responses} and "
                    + ("finding-free host observations plus " if host_observation_suffix else "")
                    + f"{engine_derived_suffix}, retained here but not evaluated by that check"
                )
            else:
                later = (
                    f"the records accepted after it through frontier {frontier.sequence} are "
                    f"{responses} and finding-free host observations, "
                    "retained here but not evaluated by that check"
                )
        else:
            later = (
                f"no cooperative material work superseded it through frontier {frontier.sequence}"
            )
        return (
            f"A check is recorded at {tested} and still contributes here: {later}. Its verdict "
            f"is current as of {tested}, not frontier {frontier.sequence}. Re-run check to "
            "evaluate the later material; routine observation can advance the ledger again. "
            "Ingestion order does not establish when observed work occurred."
        )
    if "check_not_applicable" in gap_codes:
        tested = (
            "an earlier subject frontier"
            if tested_subject_sequence is None
            else f"subject frontier {tested_subject_sequence}"
        )
        return (
            f"A check is recorded at {tested}, but material work was "
            f"{'recorded' if superseded_by_observation else 'published'} after it, so "
            f"its verdict no longer covers frontier {frontier.sequence}. Re-run check at this "
            "frontier to restore coverage."
        )
    if "check_not_recorded" in gap_codes:
        return (
            f"No check is recorded for frontier {frontier.sequence}, so no verdict contributes to "
            "this receipt's coverage."
        )
    if "check_payload_unavailable" in gap_codes:
        return (
            f"A check is recorded at frontier {frontier.sequence}, but its payload could not be "
            "read, so its verdict does not contribute to this receipt's coverage."
        )
    return ""


def _semantic_endpoint_sentence(check: CheckRecordedPayload | None) -> str:
    """Name the endpoint that served AI-powered review when it was not the primary (#582).

    Single-endpoint reviews say nothing here: the provenance already names the one binding the
    policy allows. A fallback-served review is different — the reader approved two destinations
    and must be able to see which one received the case and why the primary did not, in every
    rendering, not only the JSON document. Identifiers are closed structural identity strings,
    never provider or user text.
    """

    provenance = None if check is None else check.semantic_provenance
    if provenance is None or provenance.fallback_from is None:
        return ""
    origin = provenance.fallback_from
    attempts = _count_phrase(origin.attempted_count, "attempt", "attempts")
    return (
        f" AI-powered review was served by the fallback endpoint {provenance.provider}/"
        f"{provenance.model} ({provenance.endpoint_profile_id}@"
        f"{provenance.endpoint_profile_version}) after the primary {origin.provider}/"
        f"{origin.model} ({origin.endpoint_profile_id}@{origin.endpoint_profile_version}) "
        f"could not serve: {origin.reason.value} after {attempts}."
    )


def _task_statement_source_sentence(
    check: CheckRecordedPayload | None, records: tuple[LedgerRecord, ...]
) -> str:
    """Say what the AI-powered reviewer had of the user's request (issue #908, review 942-G4).

    A title standing in adds no gap, so without this sentence a title-only review reads like one
    that had the request. Fixed words only, derived from the ledger prefix the check tested. It
    says nothing when no AI-powered review completed, when the check already carries the
    task-statement gaps (their own prose explains it), when the receipt has no history to read,
    or when a statement-bearing event is no longer readable and the source cannot be shown.
    """

    if (
        check is None
        or check.semantic_provenance is None
        or check.semantic_status is not SemanticStatus.SUCCEEDED
        or TASK_STATEMENT_UNAVAILABLE_GAP in check.coverage.known_gaps
        or not records
    ):
        return ""
    if _provider_manifest_spec_status(check) not in {None, "complete"}:
        # The provider-bound manifest is authoritative after minimization. A recorded statement
        # may have been clipped, withheld, or reduced to title-only scope for this packet.
        return ""
    tested = tuple(
        record
        for record in records
        if record.ledger.ingestion_sequence <= check.subject_frontier.sequence
    )
    statement = current_task_statement(tested)
    if statement is not None:
        return (
            " The AI-powered reviewer received the agent's transcription of the user's request "
            f"as the task statement (source {statement.source.value}), not a host-captured prompt."
        )
    if any(may_carry_task_statement(record) for record in tested):
        return ""
    return (
        " No task statement was recorded before the AI-powered review, so the reviewer had at "
        "most the task title in place of the user's request (source "
        f"{TaskStatementSource.TASK_TITLE_ONLY.value})."
    )


_REVIEW_INPUT_SECTION_STATUSES: Final = frozenset(
    {"complete", "partial", "title_only", "missing", "withheld", "not_selected"}
)


def _provider_manifest_spec_status(check: CheckRecordedPayload | None) -> str | None:
    if check is None or not isinstance(check.review_input_manifest, Mapping):
        return None
    manifest = check.review_input_manifest
    if manifest.get("phase") != "provider_bound":
        return None
    specification = manifest.get("specification")
    if not isinstance(specification, Mapping):
        return None
    status = specification.get("status")
    return status if type(status) is str and status in _REVIEW_INPUT_SECTION_STATUSES else None


def _reviewer_sentence(check: CheckRecordedPayload | None) -> str:
    """#1118: what the applicable check's reviewer conversation read, as FinishUP recorded it.

    Closed tokens, counts, aliases and opaque ids only. The reviewer's own summary is not part of
    this structural sentence; it travels as its own fenced item (``_reviewer_advisory_item``).
    """

    record = None if check is None else reviewer_record_from_wire(check.reviewer)
    lines = render_reviewer_lines(record)
    return "" if not lines else " " + "; ".join(lines) + "."


# The fixed fence around the reviewer's own words in a receipt (#1118). The text is the applicable
# check's recorded review summary, final advisory and residual reasons included, never a FinishUP
# finding or conclusion.
REVIEWER_ADVISORY_LABEL: Final = (
    "AI-powered reviewer summary (advisory; the reviewer's own words, not a FinishUP conclusion): "
)
REVIEWER_ADVISORY_WITHHELD: Final = (
    "AI-powered reviewer summary withheld by this receipt's {profile} redaction profile; a "
    "full_local receipt shows it."
)


def _reviewer_advisory_text(check: CheckRecordedPayload | None) -> str | None:
    """The applicable check's recorded reviewer summary, when an AI-powered review produced one."""

    if (
        check is None
        or check.semantic_status is not SemanticStatus.SUCCEEDED
        or not check.review_summary
    ):
        return None
    return check.review_summary


def _reviewer_advisory_item(
    check: CheckRecordedPayload | None, profile: ReceiptRedactionProfile
) -> str | None:
    """#1118: the reviewer's final advisory and residual reasons as one fenced receipt item.

    It is a ``finding_summary`` leaf like every receipt prose item, so the result-boundary privacy
    projection governs it on every agent view. ``full_local`` carries the words; the export
    profiles carry an explicit omission instead, counted as a policy redaction.
    """

    text = _reviewer_advisory_text(check)
    if text is None:
        return None
    if profile is not ReceiptRedactionProfile.FULL_LOCAL:
        return REVIEWER_ADVISORY_WITHHELD.format(profile=profile.value)
    return clip_to_limit(
        REVIEWER_ADVISORY_LABEL + text, 8192, marker=" [reviewer summary cut]", ascii_only=False
    )


def _semantic_usage_sentence(provenance: SemanticProvenance | None) -> str:
    """Render only bounded token counters retained by AI-powered review provenance.

    Receipt text is a public projection of the canonical document.  Keep this projection useful
    for benchmark analysis while excluding provider response text, account identifiers, and any
    other runtime content.  Codex runtime evidence has the detailed counters (cached input and
    reasoning output are subsets of their parent totals); ordinary AI-powered review providers retain the
    aggregate input/output/total counters.
    """

    if provenance is None:
        return ""
    runtime = provenance.runtime_evidence
    # Codex subscription attempts dispatch under a per-check effort and output limit (issue
    # #571); name the exact selection beside the usage it produced.
    selection = (
        ""
        if runtime is None
        else (
            " AI-powered review selection: "
            f"model={provenance.model}, reasoning_effort={runtime.reasoning_effort}, "
            f"output_limit={provenance.sampling_params.max_output_tokens} tokens."
        )
    )
    usage = None if runtime is None else runtime.token_usage
    if usage is not None:
        return (
            selection + " AI-powered review attempt usage: "
            f"input={usage.input_tokens}, cached_input={usage.cached_input_tokens}, "
            f"cache_write_input={usage.cache_write_input_tokens}, output={usage.output_tokens}, "
            f"reasoning_output={usage.reasoning_output_tokens}, total={usage.total_tokens} tokens."
        )
    aggregate = provenance.token_usage
    if aggregate is None:
        return selection
    return (
        selection + " AI-powered review attempt usage: "
        f"input={aggregate.input_tokens}, output={aggregate.output_tokens}, "
        f"total={aggregate.total_tokens} tokens."
    )


_INPUT_LOSS_CAUSE = re.compile(r"Refusal cause: ([a-z_]+(?:, [a-z_]+)*)\. ")


def _input_loss_causes(context: ReceiptBuildContext) -> tuple[str, ...]:
    """Closed refusal causes the service-authored loss-lane markers disclosed (#998).

    Only ``hook_observed`` evidence written by the observation coordinator carries the fixed
    marker sentence; every token is checked against the closed cause vocabulary.
    """

    from finishup.domain.observation_budget import AdmissionLossCause

    if "observation_input_loss" not in context.coverage.known_gaps:
        return ()
    allowed = {item.value for item in AdmissionLossCause}
    hook_observed = {
        record.event_id
        for record in context.records
        if isinstance(record, AcceptedEvent)
        and PublicationChannel.HOOK_OBSERVED in record.coverage.publication_channels
    }
    causes: set[str] = set()
    for record in context.projection.evidence.values():
        if record.source_event_id not in hook_observed:
            continue
        payload = record.payload
        description = None if payload is None else payload.description
        if description is None or not description.startswith(
            "At least one non-replayable observation was lost."
        ):
            continue
        match = _INPUT_LOSS_CAUSE.search(description)
        if match is not None:
            causes.update(token for token in match.group(1).split(", ") if token in allowed)
    return tuple(sorted(causes))


# At most this many review-mode switches are named; earlier ones are counted (ADR-049).
_REVIEW_MODE_SWITCHES_LISTED: Final = 8
_REVIEW_MODE_LOCAL_REASON_TEXT: Final[Mapping[str, str]] = {
    "owner_local_only": "the owner chose local checks only for this repository",
    "route_local_only": "the host connection is registered local-only (strict route)",
    "review_disabled": "AI-powered review is turned off in the verification settings",
    "ai_review_not_set_up": "AI-powered review is not set up for this repository",
}


def _switch_credit(switch: ReviewModeSwitch, authors: Mapping[EventId, Actor]) -> str:
    """Who the ledger recorded as the switch's author, and the payload's declared authority.

    The envelope's actor and the service-derived assurance say who recorded it; the payload's
    ``authority`` is only what that author declared, so it is labelled as declared.
    """

    author = authors.get(switch.event_id)
    recorded = (
        ""
        if author is None
        else (
            f"; recorded by {author.actor_id} ({author.actor_type.value}, "
            f"{author.assurance.value.replace('_', '-')})"
        )
    )
    return f"(event {switch.event_id}{recorded}; declared authority {switch.authority})"


def _applicable_review_mode_sentence(check: CheckRecordedPayload | None) -> str:
    """How the applicable check ran, from the mode it recorded; ``""`` when it recorded none."""

    recorded = None if check is None else check.review_mode
    if recorded is None:
        return ""
    if recorded.mode is ReviewMode.AI_POWERED:
        return "The applicable check ran with AI-powered review requested."
    if recorded.local_reason is not None:
        reason = _REVIEW_MODE_LOCAL_REASON_TEXT[recorded.local_reason]
        return f"The applicable check ran local checks only (FinishUP), because {reason}."
    if recorded.source == "check_request":
        return "The applicable check ran local checks only (FinishUP), as that check asked."
    if recorded.source == "conversation_switch":
        return "The applicable check ran local checks only (FinishUP)."
    return (
        "The applicable check ran local checks only (FinishUP); AI-powered review was not "
        "requested for this task."
    )


def _review_mode_sentence(context: ReceiptBuildContext) -> str:
    """When and by whom the task switched review mode, and how its applicable check ran.

    ADR-049: names each standing ``decision_recorded`` 1.1.0 switch by ledger sequence, event id,
    the actor the ledger recorded (with its assurance) and the declared authority, never by its
    statement or rationale; then the mode the applicable check recorded. A task whose checks
    recorded no mode and that never switched (a policy that predates the setting) keeps its
    receipt bytes exactly.
    """

    check = context.applicable_check
    switches = review_mode_switches(context.projection)
    if not switches:
        return _applicable_review_mode_sentence(check)
    listed = switches[-_REVIEW_MODE_SWITCHES_LISTED:]
    earlier = len(switches) - len(listed)
    wanted = {switch.event_id for switch in listed}
    authors = {
        record.event_id: record.author for record in context.records if record.event_id in wanted
    }
    rows = "; ".join(
        ("to AI-powered review" if switch.mode is ReviewMode.AI_POWERED else "back to local checks")
        + f" at sequence {switch.sequence} {_switch_credit(switch, authors)}"
        for switch in listed
    )
    sentence = f"Review mode switches recorded for this task: {rows}."
    if earlier:
        sentence += f" {earlier} earlier switch(es) are not listed; status lists the latest."
    if check is None:
        return sentence + " No check applies to this receipt."
    if check.review_mode is None:
        return sentence + " The applicable check recorded no review mode."
    return f"{sentence} {_applicable_review_mode_sentence(check)}"


def _sections(
    *,
    include: ReceiptInclude,
    conclusion: ReceiptConclusion,
    frontier: Frontier,
    versions: ReceiptVersionSlice,
    findings: tuple[Finding, ...],
    unresolved_actionable_count: int,
    unresolved_actionable_ids: tuple[FindingId, ...],
    obligations: tuple[ReceiptObligation, ...],
    claim_refs: tuple[ClaimId, ...],
    evidence_refs: tuple[EvidenceId, ...],
    coverage: Coverage,
    redactions: tuple[ReceiptRedaction, ...],
    plan_scope: CurrentPlanScope,
    tested_subject_sequence: str | None = None,
    resolved_finding_ids: tuple[FindingId, ...] = (),
    retired_finding_count: int = 0,
    planned_retired_finding_count: int = 0,
    semantic_endpoint_sentence: str = "",
    semantic_usage_sentence: str = "",
    reviewer_sentence: str = "",
    reviewer_advisory: str | None = None,
    task_statement_source_sentence: str = "",
    resolution_explanations: tuple[str, ...] = (),
    attempt_explanations: tuple[str, ...] = (),
    check_suffix: CheckSuffixClass | None = None,
    engine_derived_suffix: str | None = None,
    host_observation_suffix: bool = False,
    input_loss_causes: tuple[str, ...] = (),
    observed_failure_sentence: str = "",
    caller_digest_counts: _CallerDigestCounts = _NO_CALLER_DIGESTS,
    limitation_response_suffix: bool = False,
    superseded_by_observation: bool = False,
    check_change_gap_texts: Mapping[str, str] | None = None,
    review_input_manifest: object | None = None,
    missing_for_assessment: object = (),
    check_totals_text: str = "",
    acknowledged_obligations: frozenset[str] = frozenset(),
    review_not_required: bool = False,
    historical_gap_codes: frozenset[str] = frozenset(),
    omitted_rows_sentence: str = "",
    closure_summary: _ClosureSummary | None = None,
    gap_effects: Mapping[str, ReceiptGapEffect] | None = None,
    review_mode_sentence: str = "",
    coordinator_failure: bool = False,
    claim_verification: tuple[str, ...] = (),
    claim_verification_limitation: str = "",
    decision_answers: Mapping[FindingId, str] | None = None,
) -> tuple[ReceiptSection, ...]:
    # Issue #1017: the limitations section lists live gaps only; the human renderings list the
    # historical ones (a later check cleared them) in their own section from the gap rows.
    gap_codes = tuple(code for code in coverage.known_gaps if code not in historical_gap_codes)
    gap_texts = check_change_gap_texts or {}
    bodies: dict[ReceiptSectionKey, str] = {}
    items: dict[ReceiptSectionKey, tuple[str, ...]] = {}
    resolved_sentence = _resolved_history_sentence(
        len(resolved_finding_ids), retired_finding_count, planned_retired_finding_count
    )

    if closure_summary is not None:
        # ADR-046: one set of counters, the reasons behind the label, and the latest check's own
        # counts under their own name (never beside the cumulative ones as a second counter).
        lead = {
            ReceiptConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS: (
                f"No unresolved local findings were recorded at frontier {frontier.sequence}."
            ),
            ReceiptConclusion.INSUFFICIENT_COVERAGE: (
                f"Coverage is insufficient at frontier {frontier.sequence}."
            ),
            ReceiptConclusion.UNRESOLVED_FINDINGS_REMAIN: (
                f"Unresolved findings remain at frontier {frontier.sequence}."
            ),
        }[conclusion]
        bodies[ReceiptSectionKey.SUMMARY] = lead + resolved_sentence + closure_summary.sentences
        if check_totals_text:
            tested = (
                "" if tested_subject_sequence is None else f" (frontier {tested_subject_sequence})"
            )
            bodies[ReceiptSectionKey.SUMMARY] += (
                f" Latest check{tested} "
                + check_totals_text.removeprefix("Totals: ").removeprefix("Totals ")
            )
    else:
        if conclusion is ReceiptConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS:
            bodies[ReceiptSectionKey.SUMMARY] = (
                f"No unresolved local findings were recorded at frontier {frontier.sequence}."
                + resolved_sentence
            )
        elif conclusion is ReceiptConclusion.INSUFFICIENT_COVERAGE:
            bodies[ReceiptSectionKey.SUMMARY] = (
                f"Coverage is insufficient at frontier {frontier.sequence}." + resolved_sentence
            )
        else:
            phrase = _count_phrase(
                unresolved_actionable_count, "actionable finding", "actionable findings"
            )
            bodies[ReceiptSectionKey.SUMMARY] = (
                f"{phrase[:1].upper() + phrase[1:]} remain unresolved at frontier "
                f"{frontier.sequence}." + resolved_sentence
            )
        if check_totals_text:
            bodies[ReceiptSectionKey.SUMMARY] += " " + check_totals_text
    bodies[ReceiptSectionKey.SUMMARY] += omitted_rows_sentence
    # The summary's items are the resolved historical finding ids: the one place every include
    # level carries, so a renderer can always separate resolved rows from current ones.
    items[ReceiptSectionKey.SUMMARY] = resolved_finding_ids

    effective_ids = frozenset(plan_scope.effective_obligation_refs or ())
    current_obligations = tuple(
        obligation for obligation in obligations if obligation.obligation_id in effective_ids
    )
    open_current = tuple(
        obligation
        for obligation in current_obligations
        if obligation.status is ReceiptObligationStatus.OPEN
        # #997: an obligation acknowledged as not done is not open work; it is counted apart.
        and obligation.obligation_id not in acknowledged_obligations
    )
    open_count = len(open_current)
    if not plan_scope.has_plan:
        bodies[ReceiptSectionKey.OUTSTANDING_WORK] = (
            "No plan is recorded; completion scope is unknown."
        )
    elif not plan_scope.readable:
        bodies[ReceiptSectionKey.OUTSTANDING_WORK] = (
            "The current plan scope is unreadable; open obligations are unknown."
        )
    elif (
        plan_scope.has_plan
        and plan_scope.declared_obligation_count == 0
        and plan_scope.no_obligations_reason is None
    ):
        bodies[ReceiptSectionKey.OUTSTANDING_WORK] = "Completion scope was never declared."
    elif (
        plan_scope.has_plan
        and plan_scope.declared_obligation_count == 0
        and plan_scope.no_obligations_reason is not None
    ):
        bodies[ReceiptSectionKey.OUTSTANDING_WORK] = (
            f"The plan declared none, reason: {plan_scope.no_obligations_reason.value}."
        )
    elif (
        plan_scope.has_plan
        and plan_scope.declared_obligation_count is not None
        and plan_scope.declared_obligation_count > 0
        and len(current_obligations) != plan_scope.declared_obligation_count
    ):
        bodies[ReceiptSectionKey.OUTSTANDING_WORK] = (
            "Declared obligation status is unavailable; open obligations are unknown."
        )
    elif (
        plan_scope.has_plan
        and plan_scope.declared_obligation_count is not None
        and plan_scope.declared_obligation_count > 0
        and len(current_obligations) == plan_scope.declared_obligation_count
        and all(
            obligation.status is ReceiptObligationStatus.RESOLVED
            for obligation in current_obligations
        )
    ):
        bodies[ReceiptSectionKey.OUTSTANDING_WORK] = "Declared obligations are all resolved."
    elif open_count == 0:
        bodies[ReceiptSectionKey.OUTSTANDING_WORK] = "No open obligations are recorded."
    elif open_count == 1:
        bodies[ReceiptSectionKey.OUTSTANDING_WORK] = "One obligation remains open."
    else:
        bodies[ReceiptSectionKey.OUTSTANDING_WORK] = f"{open_count} obligations remain open."
    acknowledged_current = sum(
        obligation.obligation_id in acknowledged_obligations for obligation in current_obligations
    )
    if acknowledged_current and ReceiptSectionKey.OUTSTANDING_WORK in bodies:
        noun = "obligation is" if acknowledged_current == 1 else "obligations are"
        bodies[ReceiptSectionKey.OUTSTANDING_WORK] += (
            f" {acknowledged_current} {noun} acknowledged as not done (not counted as open)."
        )
    items[ReceiptSectionKey.OUTSTANDING_WORK] = tuple(
        obligation.obligation_id for obligation in open_current
    )

    actionable_count = (
        unresolved_actionable_count if closure_summary is None else closure_summary.unresolved
    )
    if actionable_count == 0 and conclusion is not ReceiptConclusion.INSUFFICIENT_COVERAGE:
        bodies[ReceiptSectionKey.FINDINGS_AND_DISPOSITIONS] = (
            "No findings remain open." + resolved_sentence
        )
    elif actionable_count == 0:
        bodies[ReceiptSectionKey.FINDINGS_AND_DISPOSITIONS] = (
            "No actionable finding is selected, but weak coverage prevents the strong conclusion."
            + resolved_sentence
        )
    elif actionable_count == 1:
        bodies[ReceiptSectionKey.FINDINGS_AND_DISPOSITIONS] = (
            "One actionable finding remains unresolved." + resolved_sentence
        )
    else:
        bodies[ReceiptSectionKey.FINDINGS_AND_DISPOSITIONS] = (
            f"{actionable_count} actionable findings remain unresolved." + resolved_sentence
        )
    if closure_summary is not None and closure_summary.findings_note:
        bodies[ReceiptSectionKey.FINDINGS_AND_DISPOSITIONS] += " " + closure_summary.findings_note
    choices = tuple(finding for finding in findings if finding.kind is FindingKind.DECISION_NEEDED)
    answers: Mapping[FindingId, str] = {} if decision_answers is None else decision_answers
    if choices and actionable_count == 0:
        bodies[ReceiptSectionKey.FINDINGS_AND_DISPOSITIONS] = (
            "No actionable finding remains open. Advisory decision choices stay on record."
            + resolved_sentence
        )
    if resolution_explanations:
        for explanation in resolution_explanations:
            current = bodies[ReceiptSectionKey.FINDINGS_AND_DISPOSITIONS]
            if len((current + explanation).encode("utf-8")) > 30000:
                bodies[ReceiptSectionKey.FINDINGS_AND_DISPOSITIONS] += (
                    " Additional explanations omitted; inspect status view=findings."
                )
                break
            bodies[ReceiptSectionKey.FINDINGS_AND_DISPOSITIONS] += " " + explanation
    items[ReceiptSectionKey.FINDINGS_AND_DISPOSITIONS] = tuple(
        finding_id_value
        for finding_id_value in unresolved_actionable_ids
        if any(finding.finding_id == finding_id_value for finding in findings)
    )
    # #1146: model-derived choices belong in fenced prose leaves, never the structural body.
    # ``findings`` has already passed the receipt profile; redacted-share drops semantic rows.
    items[ReceiptSectionKey.FINDINGS_AND_DISPOSITIONS] += tuple(
        clip_to_limit(
            (
                "AI-powered decision recorded"
                if finding.finding_id in answers
                else "AI-powered decision needed"
            )
            + f" (advisory, non-blocking) {finding.finding_id}: "
            f"{finding.summary}\n{finding.detail}"
            + (
                f"\nInterpretation: {finding.challenge.discrepancy}"
                f"\nAlternative: {finding.challenge.alternative_interpretation}"
                f"\nUncertainty: {finding.challenge.uncertainty}"
                if finding.challenge is not None
                else ""
            )
            + (
                f"\nAgent decision (self-reported): {answers[finding.finding_id]}"
                if finding.finding_id in answers
                else ""
            ),
            8192,
            marker=" [decision detail cut; inspect status view=findings]",
            ascii_only=False,
        )
        for finding in choices
    )

    claim_phrase = _count_phrase(len(claim_refs), "claim reference", "claim references")
    evidence_phrase = _count_phrase(len(evidence_refs), "evidence reference", "evidence references")
    bodies[ReceiptSectionKey.EVIDENCE_AND_CLAIM_BASIS] = (
        f"The receipt retains {claim_phrase} and {evidence_phrase}."
    )
    items[ReceiptSectionKey.EVIDENCE_AND_CLAIM_BASIS] = (*claim_refs, *evidence_refs)

    if attempt_explanations:
        bodies[ReceiptSectionKey.EVIDENCE_AND_CLAIM_BASIS] += " " + " ".join(attempt_explanations)
    if claim_verification:
        # Issue #1079: the ledger pairing. A final-message attestation is not this text.
        bodies[ReceiptSectionKey.EVIDENCE_AND_CLAIM_BASIS] += " " + " ".join(claim_verification)

    if gap_codes:
        limited_by = _limited_by(gap_codes, gap_effects)
        not_requested = SEMANTIC_REVIEW_NOT_REQUESTED_GAP in gap_codes
        not_run = (
            SEMANTIC_REVIEW_NOT_CONFIGURED_GAP in gap_codes
            or SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP in gap_codes
        )
        # A check that ran and succeeded still contributes nothing once material work lands
        # after it. Saying only `check_not_applicable` next to a fresh successful check reads as
        # a contradiction; the 2026-07-27 dogfood could not tell which of four readings was meant.
        check_sentence = _check_coverage_sentence(
            gap_codes,
            frontier,
            tested_subject_sequence,
            check_suffix,
            engine_derived_suffix=engine_derived_suffix,
            host_observation_suffix=host_observation_suffix,
            limitation_response_suffix=limitation_response_suffix,
            superseded_by_observation=superseded_by_observation,
        )
        if check_sentence:
            gap_body = f"{check_sentence} Coverage is limited by: {', '.join(gap_codes)}."
        elif SEMANTIC_REVIEW_SKIPPED_INSUFFICIENT_PACKET_GAP in gap_codes:
            gap_body = (
                "AI-powered review was skipped: the reviewer twice in a row, or four times since "
                "the last assessed review, could not assess the review packet or a finding the "
                "agent answered (a FinishUP limit). "
                f"Coverage is limited by: {limited_by}."
            )
        elif not_requested and SEMANTIC_REVIEW_DEFERRED_BEFORE_FIRST_EDIT_GAP in gap_codes:
            # Issue #1046: the applicable check ran before any material edit. JSON, markdown,
            # and text all carry this section body.
            gap_body = f"{DEFERRED_BEFORE_FIRST_EDIT_TEXT} Coverage is limited by: {limited_by}."
        elif not_requested:
            gap_body = (
                "AI-powered review was not requested (local-only check). "
                f"Coverage is limited by: {limited_by}."
            )
        elif not_run:
            gap_body = (
                f"AI-powered relevance review was not run. Coverage is limited by: {limited_by}."
            )
        elif OPTIONAL_SEMANTIC_REVIEW_REGISTRATION_DRIFT_GAP in gap_codes:
            # The strict ceiling blocked this process while the last install applied the
            # policy route (issue #537). The disagreement is what is proven: whether this
            # strict route was intended is the owner's to say, and a route reached outside
            # the install ceremony is a legitimate owner action, so the recovery is offered
            # conditionally rather than asserted as a stale process. A ceiling with no
            # applied-policy record keeps the generic wording below.
            gap_body = (
                "AI-powered review was blocked by the strict route ceiling, but the last "
                "install applied the policy route. If this strict route was not intended, "
                "re-run `finishup integrate codex mcp preview` and "
                "`finishup integrate codex mcp install --route-profile policy`, then start a "
                "fresh Codex process. "
                f"Coverage is limited by: {limited_by}."
            )
        else:
            gap_body = f"Coverage is limited by: {limited_by}."
        if not_requested and review_not_required:
            # Issue #986 (owner decision E2): the applicable check's route did not require it.
            gap_body += (
                " The check's route did not require AI-powered review, so its absence is "
                "disclosed and does not bound the conclusion."
            )
        if PREEXISTING_TEST_INFORMATIONAL_GAPS & set(gap_codes):
            gap_body += (
                " Existing test-file edits are listed for review; their presence alone does not "
                "block this receipt."
            )
        if COMPLETION_CLAIM_OUTSIDE_PLAN_GAP in gap_codes:
            gap_body += (
                " A completion claim covers obligations outside the effective plan. " + SCOPE_REPAIR
            )
        if COMPLETION_PLAN_NOT_CLAIMED_GAP in gap_codes:
            gap_body += (
                " Some declared plan obligations are outside a completion claim; whole-plan completion is not established. "
                + SCOPE_REPAIR
            )
            bodies[ReceiptSectionKey.OUTSTANDING_WORK] += (
                " Declared scope remains outside a completion claim, regardless of obligation resolution."
            )
        if "routine_read_detail_omitted" in gap_codes:
            gap_body += (
                " Successful routine reads are represented by bounded source summaries; "
                "their individual content was not retained. Summary coverage does not "
                "establish verification or selection for this check."
            )
        # Why the check-time change was unavailable (ADR-031): one fixed sentence per closed code.
        for code in gap_codes:
            sentence = gap_texts.get(code)
            if sentence is not None:
                gap_body += " " + sentence
        if "observation_input_loss" in gap_codes:
            gap_body += (
                " Some native observation inputs could not be retained. This historical "
                "loss remains a limitation after queue recovery; rerunning a read supplies "
                "evidence for its new time and state only."
            )
            if input_loss_causes:
                gap_body += " Recorded refusal cause: " + ", ".join(input_loss_causes) + "."
        if CALLER_DIGEST_PROVENANCE_GAPS & set(gap_codes):
            gap_body += " " + _caller_digest_sentence(caller_digest_counts)
        # What the AI-powered reviewer knew of the user's request (issue #908), in fixed words.
        for code in (
            TASK_STATEMENT_UNAVAILABLE_GAP,
            TASK_STATEMENT_NOT_AUTHORIZED_GAP,
            TASK_STATEMENT_NOT_SUPPLIED_GAP,
        ):
            detail = task_statement_gap_detail(code)
            if code in gap_codes and detail is not None:
                gap_body += " " + detail
        bodies[ReceiptSectionKey.LIMITATIONS_AND_COVERAGE] = gap_body
        items[ReceiptSectionKey.LIMITATIONS_AND_COVERAGE] = gap_codes
    elif redactions:
        bodies[ReceiptSectionKey.LIMITATIONS_AND_COVERAGE] = (
            "Visibility is reduced by recorded redactions; coverage is not proof of correctness."
        )
        items[ReceiptSectionKey.LIMITATIONS_AND_COVERAGE] = ()
    else:
        bodies[ReceiptSectionKey.LIMITATIONS_AND_COVERAGE] = (
            "Coverage is bounded to the recorded evidence and is not proof of correctness."
        )
        items[ReceiptSectionKey.LIMITATIONS_AND_COVERAGE] = ()
    if coordinator_failure:
        # Issue #1077: the gap code stays semantic_relevance_review_not_run. The limitations
        # the reader sees name the fault inside FinishUP, on every rendering of this section.
        # Issue #1079 item 3 names the same failure as a closing-review limit. One sentence
        # covers both: the readiness checklist, not this section, says not to send it again.
        body = bodies[ReceiptSectionKey.LIMITATIONS_AND_COVERAGE]
        lead = "AI-powered relevance review was not run."
        if lead in body:
            body = body.replace(lead, COORDINATOR_FAILURE_LIMITATION, 1)
        elif COORDINATOR_FAILURE_LIMITATION not in body:
            body = f"{body} {COORDINATOR_FAILURE_LIMITATION}"
        bodies[ReceiptSectionKey.LIMITATIONS_AND_COVERAGE] = body
    if observed_failure_sentence:
        bodies[ReceiptSectionKey.LIMITATIONS_AND_COVERAGE] += " " + observed_failure_sentence
    bodies[ReceiptSectionKey.LIMITATIONS_AND_COVERAGE] += task_statement_source_sentence
    review_input_coverage_note = render_review_input_manifest_coverage_note(
        review_input_manifest,
        missing_for_assessment,
    )
    compat_manifest_line = render_review_input_manifest_compat_line(review_input_manifest)
    if compat_manifest_line:
        bodies[ReceiptSectionKey.LIMITATIONS_AND_COVERAGE] += " " + compat_manifest_line
    # ADR-049: only a task that switched its review mode carries this closing sentence, so every
    # receipt of a task without a switch keeps its exact bytes.
    if review_mode_sentence:
        bodies[ReceiptSectionKey.LIMITATIONS_AND_COVERAGE] += " " + review_mode_sentence
    # #1079: a holed projection omits the pairing for that obligation. The limitation is ids
    # only, or one fixed sentence, so the receipt still renders.
    if claim_verification_limitation:
        bodies[ReceiptSectionKey.LIMITATIONS_AND_COVERAGE] += " " + claim_verification_limitation

    policy_rows = "; ".join(
        f"{entry.policy_id} {entry.policy_version}" for entry in versions.policy_versions
    )
    bodies[ReceiptSectionKey.VERSION_AND_POLICY_IDENTITY] = (
        f"Engine {versions.engine_version}; protocol {versions.protocol_version}; {policy_rows}."
        + semantic_endpoint_sentence
        + semantic_usage_sentence
        + reviewer_sentence
    )
    items[ReceiptSectionKey.VERSION_AND_POLICY_IDENTITY] = ()

    if reviewer_advisory is not None:
        # The reviewer's own words are their own fenced item, never part of FinishUP's prose.
        items[ReceiptSectionKey.LIMITATIONS_AND_COVERAGE] = (
            *items[ReceiptSectionKey.LIMITATIONS_AND_COVERAGE],
            reviewer_advisory,
        )
    finished = {key: _finish_section(bodies[key], items[key]) for key in _SECTION_KEYS[include]}
    return tuple(
        ReceiptSection(
            key=key,
            title=_SECTION_TITLES[key],
            body=finished[key][0],
            items=finished[key][1],
            coverage_note=(
                review_input_coverage_note
                if key is ReceiptSectionKey.LIMITATIONS_AND_COVERAGE
                else None
            ),
        )
        for key in _SECTION_KEYS[include]
    )


@dataclass(frozen=True, slots=True)
class _ClosureSummary:
    """The Summary and Findings sentences of one receipt, from the one set of counters."""

    sentences: str
    unresolved: int
    findings_note: str


_DISCLOSED_BASIS_LABELS: Final[Mapping[str, str]] = {
    "self_verified": "self-verified",
    "disputed_after_rebuttal": "disputed after rebuttal",
    "limitation_disclosed": "verification limit",
    "acknowledged_not_done_bookkeeping": "acknowledged bookkeeping",
    "failed_run_disclosed": "disclosed failed command",
    "rejected_review_unavailable": "rejection no reviewer can rule on",
    "rejection_accepted": "rejection accepted",
}


def _plural(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


def _closure_summary(basis: ClosureBasis, prediction: ReceiptPrediction) -> _ClosureSummary:
    """Build the receipt's counters sentence from ``ClosureCounts`` (one source, no second counter)."""

    counts = closure_counts(basis.findings, basis.obligations)
    resolved = sum(
        item.closure_class is ObligationClosureClass.RESOLVED for item in basis.obligations
    )
    seen: dict[FindingId, FindingClosure] = {}
    for closure in basis.findings:
        if closure.counts_as not in seen or closure.finding_id == closure.counts_as:
            seen[closure.counts_as] = closure
    breakdown: Counter[str] = Counter(
        _DISCLOSED_BASIS_LABELS.get(closure.basis, closure.basis)
        for closure in seen.values()
        if closure.closure_class is FindingClosureClass.SETTLED_DISCLOSED
    )
    findings = f" Findings: {counts.findings_to_do} to do"
    if counts.findings_awaiting_ruling:
        findings += f" ({counts.findings_awaiting_ruling} awaiting a reviewer ruling)"
    findings += f", {counts.findings_unmet} unmet (acknowledged requirement)"
    findings += f", {counts.findings_disclosed} disclosed"
    if breakdown:
        findings += " (" + ", ".join(f"{n} {label}" for label, n in sorted(breakdown.items())) + ")"
    if counts.findings_to_disclose:
        findings += f", {counts.findings_to_disclose} to disclose"
    findings += "."
    obligations = (
        f" Obligations: {resolved} resolved, {counts.obligations_open} open, "
        f"{counts.obligations_acknowledged} acknowledged not done, "
        f"{counts.obligations_disclosed} disclosed."
    )
    why = ""
    if prediction.conclusion is not PredictionConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS:
        phrases = reason_phrases(prediction.reasons)
        if phrases:
            more = prediction.reason_total - len(prediction.reasons)
            why = (
                f" Why {prediction.conclusion.value}: {', '.join(phrases)}"
                + (f" (+{more} more)" if more > 0 else "")
                + "."
            )
    notes: list[str] = []
    if counts.findings_awaiting_ruling:
        notes.append(
            f"{_plural(counts.findings_awaiting_ruling, 'rejected finding awaits', 'rejected findings await')}"
            " a reviewer ruling; the agent disputes "
            f"{'it' if counts.findings_awaiting_ruling == 1 else 'them'} and the reviewer has not ruled."
        )
    if counts.findings_to_disclose:
        notes.append(
            f"{_plural(counts.findings_to_disclose, 'limitation', 'limitations')} the reviewer "
            "asked the agent to state "
            f"{'has' if counts.findings_to_disclose == 1 else 'have'} not been disclosed."
        )
    return _ClosureSummary(
        findings + obligations + why,
        counts.findings_to_do + counts.findings_unmet,
        " ".join(notes),
    )


def _limited_by(gap_codes: tuple[str, ...], effects: Mapping[str, ReceiptGapEffect] | None) -> str:
    """List the live gaps, naming apart the ones that only disclose (ADR-046).

    A receipt that bounds on one gap and merely discloses five others used to list all six as
    "limited by", so a reader could not tell which gap decided the label. Without recorded effects
    (an artifact older than the effect rows) the list is the flat one it always was.
    """

    if effects is None or not all(code in effects for code in gap_codes):
        return ", ".join(gap_codes)
    bounding = [code for code in gap_codes if effects[code] is ReceiptGapEffect.BOUNDS]
    disclosed = [code for code in gap_codes if effects[code] is ReceiptGapEffect.DISCLOSED]
    if bounding and disclosed:
        return (
            f"{', '.join(bounding)} (these bound the conclusion). Also disclosed, not bounding "
            f"the conclusion: {', '.join(disclosed)}"
        )
    if disclosed:
        return f"{', '.join(disclosed)} (disclosed; none of these bounds the conclusion)"
    return f"{', '.join(bounding)} (these bound the conclusion)"


def _finding_keep_rank(
    finding: Finding,
    states_by_id: Mapping[FindingId, ReceiptFindingState],
    unresolved_actionable: frozenset[FindingId],
) -> int:
    """0 unresolved actionable, 1 a terminal state the document discloses, 2 other, 3 resolved."""

    if finding.finding_id in unresolved_actionable:
        return 0
    state = states_by_id[finding.finding_id]
    if (
        state.acknowledged_not_done
        or state.rejection_accepted
        or state.self_verified
        or state.disputed_after_rebuttal
    ):
        return 1
    return 3 if state.resolved else 2


def build_receipt(
    context: ReceiptBuildContext,
    receipt_id: ReceiptId,
    task_id: TaskId,
    session_id: SessionId,
    generated_at: Timestamp,
    versions: ReceiptVersionSlice,
    redaction_profile: ReceiptRedactionProfile,
    include: ReceiptInclude,
) -> ReceiptDocument:
    """Build the one immutable canonical receipt for a complete frozen context."""

    if (
        type(context) is not ReceiptBuildContext
        or type(versions) is not ReceiptVersionSlice
        or type(redaction_profile) is not ReceiptRedactionProfile
        or type(include) is not ReceiptInclude
    ):
        raise ValueError(_CONTEXT_INVALID)
    states_by_id = {state.finding_id: state for state in context.finding_states}
    findings = tuple(
        cast(Finding, context.projection.findings[state.finding_id].payload)
        for state in context.finding_states
    )
    # A ``rejection_accepted`` row stops blocking only on an artifact that also discloses it in its
    # own section (issue #905); an older artifact has no such section, so there it still blocks.
    settles_rejections = receipt_document_carries_terminal_sections(versions)
    # The closure classes (ADR-046) decide what is unresolved: a finding whose receipt effect is
    # ``unresolved_findings_remain`` (open, awaiting a ruling, or an acknowledged requirement).
    # ``self_verified``, disputed, disclosed-limitation and bookkeeping-acknowledged findings stay
    # disclosed by id but are not agent work and cap the conclusion at ``insufficient_coverage``.
    closures = _context_closures(context, terminal_sections=settles_rejections)
    closure_by_id = {closure.finding_id: closure for closure in closures}
    unresolved_actionable = tuple(
        finding
        for finding in findings
        if (closure := closure_by_id.get(finding.finding_id)) is not None
        and closure.receipt_effect is ReceiptEffect.UNRESOLVED_FINDINGS_REMAIN
    )
    # Issue #997: obligations the agent acknowledged as not done (ADR-032 slice C).
    acknowledged_obligations = tuple(
        sorted(acknowledged_obligation_ids(context.projection), key=_ascii_key)
    )[:100]
    # Issue #1017: only the 1.3.0 artifact can mark a gap historical; earlier artifacts keep
    # every gap live, exactly as they were issued.
    historical = dict(context.historical_gaps) if settles_rejections else {}
    obligation_classes = tuple(
        obligation_closures(context.projection, records=context.records).values()
    )
    basis = closure_basis_from_context(
        context, terminal_sections=settles_rejections, obligations=obligation_classes
    )
    prediction = predict_receipt_conclusion(basis)
    conclusion = ReceiptConclusion(prediction.conclusion.value)
    closure_summary = _closure_summary(basis, prediction) if settles_rejections else None
    # The same judgment the conclusion used says, per live gap, whether it bounds or only
    # discloses (ADR-046); an artifact older than the effect rows records none.
    gap_context = _gap_context(context, frozenset(historical))
    gap_effects: dict[str, ReceiptGapEffect] | None = (
        {
            gap.code: (
                ReceiptGapEffect.BOUNDS
                if gap_effect(gap.code, gap_context).kind.bounds
                else ReceiptGapEffect.DISCLOSED
            )
            for gap in context.gaps
            if gap.code not in historical
        }
        if settles_rejections
        else None
    )
    obligations = _select_obligations(context, findings)
    responses = _select_responses(context, frozenset(finding.finding_id for finding in findings))
    claim_refs = _select_claim_refs(context, findings)
    evidence_refs = _select_evidence_refs(context, claim_refs, obligations, responses)
    gaps = _select_gaps(context, historical, gap_effects)
    children, omitted_child_findings = _receipt_children(context.lineage)
    (
        retained_findings,
        retained_obligations,
        retained_responses,
        retained_gaps,
        redactions,
    ) = _apply_profile(
        context,
        redaction_profile,
        findings,
        obligations,
        responses,
        gaps,
    )
    # Past the document's row bounds the receipt keeps what matters most -- unresolved actionable
    # findings, the terminal states the document discloses by id, open obligations, live gaps --
    # and counts the rest in the summary (tb4n3 RC-2, A6).
    # A finding the agent still owes a move on (including a limitation to disclose) is kept first.
    unresolved_ids = frozenset(
        closure.finding_id
        for closure in closures
        if closure.closure_class
        in {
            FindingClosureClass.AGENT_WORK,
            FindingClosureClass.AWAITING_RULING,
            FindingClosureClass.SETTLED_UNMET,
        }
    )
    # The summary section's items name every resolved finding the document retains (the only
    # resolution flag a receipt carries), and a section holds at most 64 items: keep no more
    # resolved history than that, or a retained resolved row would read as unresolved.
    retained_findings, omitted_resolved = _keep_by_rank(
        retained_findings,
        _SECTION_ITEM_CAP,
        lambda finding: 1 if states_by_id[finding.finding_id].resolved else 0,
        cap_rank=1,
    )
    retained_findings, omitted_findings = _keep_by_rank(
        retained_findings,
        _DOCUMENT_ROW_CAP,
        lambda finding: _finding_keep_rank(finding, states_by_id, unresolved_ids),
    )
    omitted_findings += omitted_resolved
    retained_obligations, omitted_obligations = _keep_by_rank(
        retained_obligations,
        _DOCUMENT_ROW_CAP,
        lambda obligation: 0 if obligation.status is ReceiptObligationStatus.OPEN else 1,
    )
    kept_finding_ids = frozenset(finding.finding_id for finding in retained_findings)
    retained_responses, omitted_responses = _keep_by_rank(
        retained_responses,
        _DOCUMENT_ROW_CAP,
        lambda response: 0 if response.finding_id in kept_finding_ids else 1,
    )
    claim_refs, omitted_claims = (
        claim_refs[:_DOCUMENT_ROW_CAP],
        max(0, len(claim_refs) - _DOCUMENT_ROW_CAP),
    )
    evidence_refs, omitted_evidence = (
        evidence_refs[:_DOCUMENT_ROW_CAP],
        max(0, len(evidence_refs) - _DOCUMENT_ROW_CAP),
    )
    # A cleared (historical) gap row is the only thing that keeps its code from reading as a
    # current limitation, while a live code stays in the coverage list and the limitations
    # section whether or not its detail row is kept: cleared rows are kept first.
    retained_gaps, omitted_gaps = _keep_by_rank(
        retained_gaps,
        _GAP_ROW_CAP,
        lambda gap: 0 if gap.status is ReceiptGapStatus.HISTORICAL else 1,
    )
    omitted_rows = {
        "finding": omitted_findings,
        "obligation": omitted_obligations,
        "response": omitted_responses,
        "claim reference": omitted_claims,
        "evidence reference": omitted_evidence,
        "gap detail row": omitted_gaps,
        "child finding": omitted_child_findings,
    }
    engine_derived_suffix, host_observation_suffix, limitation_response_suffix = (
        _suffix_record_kinds(context)
    )
    # Resolved history is named only for rows the profile retains: a profile that omits a
    # finding row must not leak its id through the summary items.
    retained_ids = frozenset(finding.finding_id for finding in retained_findings)
    resolved_finding_ids = tuple(
        sorted(
            (
                state.finding_id
                for state in context.finding_states
                if state.resolved and state.finding_id in retained_ids
            ),
            key=_ascii_key,
        )
    )
    proof_state_cache: dict[tuple[int, int, str], ProjectionState | None] = {}
    claim_pairing, claim_pairing_limitation = claim_verification_report(
        context.projection, context.records
    )
    # The export profiles clear gap details; the sections they keep never copy a path (#1044).
    name_paths = redaction_profile is ReceiptRedactionProfile.FULL_LOCAL
    sections = _sections(
        check_change_gap_texts={
            code: text
            for code in context.coverage.known_gaps
            if code not in historical
            and (text := _check_change_gap_text(context, code, name_paths=name_paths)) is not None
        },
        include=include,
        conclusion=conclusion,
        frontier=context.subject_frontier,
        versions=versions,
        findings=retained_findings,
        decision_answers={
            response.finding_id: response.reason
            for response in retained_responses
            if response.disposition
            in {ResponseDisposition.ACKNOWLEDGED, ResponseDisposition.REJECTED}
            and response.reason
            and response.reason.strip()
        },
        unresolved_actionable_count=len(unresolved_actionable),
        unresolved_actionable_ids=tuple(finding.finding_id for finding in unresolved_actionable),
        obligations=retained_obligations,
        claim_refs=claim_refs,
        evidence_refs=evidence_refs,
        coverage=context.coverage,
        historical_gap_codes=frozenset(historical),
        redactions=redactions,
        plan_scope=current_plan_scope(
            context.projection.plans,
            context.projection.coverage_gaps,
        ),
        tested_subject_sequence=(
            None
            if context.projection.latest_tested_state is None
            else str(context.projection.latest_tested_state.subject_frontier.sequence)
        ),
        resolved_finding_ids=resolved_finding_ids,
        retired_finding_count=_retired_count(
            context.projection, resolved_finding_ids, planned=False
        ),
        planned_retired_finding_count=_retired_count(
            context.projection, resolved_finding_ids, planned=True
        ),
        semantic_endpoint_sentence=_semantic_endpoint_sentence(context.applicable_check),
        review_not_required=route_did_not_require_review(context.applicable_check),
        task_statement_source_sentence=_task_statement_source_sentence(
            context.applicable_check, context.records
        ),
        review_mode_sentence=_review_mode_sentence(context),
        coordinator_failure=(
            context.applicable_check is not None
            and context.applicable_check.semantic_reason is SemanticReason.COORDINATOR_FAILURE
        ),
        semantic_usage_sentence=_semantic_usage_sentence(
            None
            if context.applicable_check is None
            else context.applicable_check.semantic_provenance
        ),
        reviewer_sentence=_reviewer_sentence(context.applicable_check),
        reviewer_advisory=_reviewer_advisory_item(context.applicable_check, redaction_profile),
        attempt_explanations=tuple(
            f"{obligation.obligation_id} command item {attempt.requested_item_index}: {attempt.relation}. "
            "This relation concerns the attempt only, not command success."
            for obligation in retained_obligations[:10]
            for attempt in command_attempts(
                context.projection, context.records, obligation.obligation_id
            )[:10]
        )
        if context.records
        else (),
        resolution_explanations=tuple(
            f"{finding.finding_id}: "
            + finding_resolution_explanation(
                context.projection,
                finding.finding_id,
                context.records,
                proof_state_cache=proof_state_cache,
            )
            + _failed_command_trigger(context.projection, finding.finding_id)
            for finding in retained_findings[:10]
        )
        if context.records
        else (),
        check_suffix=context.check_suffix,
        engine_derived_suffix=engine_derived_suffix,
        host_observation_suffix=host_observation_suffix,
        input_loss_causes=_input_loss_causes(context),
        observed_failure_sentence=_observed_failure_history_sentence(context),
        acknowledged_obligations=frozenset(acknowledged_obligation_ids(context.projection)),
        caller_digest_counts=_caller_digest_counts(context),
        limitation_response_suffix=limitation_response_suffix,
        superseded_by_observation=(
            context.check_standing is not None
            and context.check_standing.superseded_by is not None
            and context.check_standing.superseded_by.observation_authored
        ),
        review_input_manifest=(
            None
            if context.applicable_check is None
            else context.applicable_check.review_input_manifest
        ),
        missing_for_assessment=(
            ()
            if context.applicable_check is None
            else context.applicable_check.missing_for_assessment
        ),
        check_totals_text=(
            ""
            if context.applicable_check is None
            else render_check_totals(context.applicable_check.totals)
        ),
        omitted_rows_sentence=_omitted_rows_sentence(omitted_rows),
        closure_summary=closure_summary,
        gap_effects=gap_effects,
        claim_verification=claim_pairing,
        claim_verification_limitation=claim_pairing_limitation,
    )
    suppressed_count = (
        0 if context.applicable_check is None else context.applicable_check.suppressed_count
    )
    terminal_sections = settles_rejections
    acknowledged_not_done_ids = tuple(
        sorted(
            (
                state.finding_id
                for state in context.finding_states
                if state.acknowledged_not_done and state.finding_id in retained_ids
            ),
            key=_ascii_key,
        )
        if terminal_sections
        else ()
    )
    rejection_accepted_ids = tuple(
        sorted(
            (
                state.finding_id
                for state in context.finding_states
                if state.rejection_accepted and state.finding_id in retained_ids
            ),
            key=_ascii_key,
        )
        if terminal_sections
        else ()
    )
    self_verified_ids = tuple(
        sorted(
            (
                state.finding_id
                for state in context.finding_states
                if state.self_verified and state.finding_id in retained_ids
            ),
            key=_ascii_key,
        )
        if terminal_sections
        else ()
    )
    disputed_ids = tuple(
        sorted(
            (
                state.finding_id
                for state in context.finding_states
                if state.disputed_after_rebuttal and state.finding_id in retained_ids
            ),
            key=_ascii_key,
        )
        if terminal_sections
        else ()
    )
    limitation_disclosed_ids = (
        tuple(
            sorted(
                (
                    closure.finding_id
                    for closure in closures
                    if closure.basis == "limitation_disclosed"
                    and closure.finding_id in retained_ids
                ),
                key=_ascii_key,
            )
        )
        if terminal_sections
        else ()
    )
    duplicate_links = (
        tuple(
            ReceiptDuplicateLink(state.finding_id, state.duplicate_of_finding_id)
            for state in sorted(
                context.finding_states, key=lambda item: _ascii_key(item.finding_id)
            )
            if state.duplicate_of_finding_id is not None and state.finding_id in retained_ids
        )[:100]
        if terminal_sections
        else ()
    )
    return ReceiptDocument(
        receipt_id=receipt_id,
        task_id=task_id,
        session_id=session_id,
        generated_at=generated_at,
        subject_frontier=context.subject_frontier,
        conclusion=conclusion,
        suppressed_finding_count=suppressed_count,
        versions=versions,
        coverage=context.coverage,
        findings=retained_findings,
        obligations=retained_obligations,
        responses=retained_responses,
        claim_refs=claim_refs,
        evidence_refs=evidence_refs,
        gaps=retained_gaps,
        redactions=redactions,
        sections=sections,
        children=children,
        semantic_provenance=(
            None
            if context.applicable_check is None
            else context.applicable_check.semantic_provenance
        ),
        semantic_status=(
            SemanticStatus.UNAVAILABLE
            if terminal_sections
            and context.applicable_check is not None
            and context.applicable_check.semantic_reason is SemanticReason.ROUND_LIMIT_UNASSESSABLE
            else None
        ),
        semantic_reason=(
            SemanticReason.ROUND_LIMIT_UNASSESSABLE
            if terminal_sections
            and context.applicable_check is not None
            and context.applicable_check.semantic_reason is SemanticReason.ROUND_LIMIT_UNASSESSABLE
            else None
        ),
        acknowledged_not_done_finding_ids=acknowledged_not_done_ids,
        rejection_accepted_finding_ids=rejection_accepted_ids,
        self_verified_finding_ids=self_verified_ids,
        disproved_self_verified_finding_ids=tuple(
            finding
            for finding in self_verified_ids
            if (row := context.projection.findings.get(finding)) is not None
            and row.standing_position is not None
            and row.standing_position.kind == "rejected"
        ),
        disputed_after_rebuttal_finding_ids=disputed_ids,
        duplicate_finding_links=duplicate_links,
        # Issue #984 (D7a): the acknowledged findings whose premise the reviewer disputes.
        premise_disputed_finding_ids=tuple(
            item
            for item in premise_disputed_finding_ids(context.projection)
            if item in acknowledged_not_done_ids
        ),
        limitation_disclosed_finding_ids=limitation_disclosed_ids,
        conclusion_basis=(
            None
            if not settles_rejections
            else ReceiptConclusionBasis(
                tuple(
                    ReceiptConclusionReason(
                        reason.code,
                        reason.rule,
                        reason.count,
                        reason.refs,
                        reason.since_frontier,
                    )
                    for reason in prediction.reasons
                ),
                prediction.reason_total,
            )
        ),
        acknowledged_not_done_obligation_ids=(
            acknowledged_obligations if terminal_sections else ()
        ),
        # Issue #995: the agent's disclosed assumptions and verification limits, ids and kind
        # only, on an artifact that carries the 1.3.0 sections. They never change the conclusion.
        disclosed_assumptions=(
            tuple(
                ReceiptDisclosure(item.obligation_id, item.kind, item.decision_event_id)
                for item in disclosure_declarations(context.projection)[:64]
            )
            if terminal_sections
            else ()
        ),
        semantic_withheld_items=tuple(
            ReceiptSemanticWithheldItem(item_id=item_id)
            for item_id in (
                ()
                if context.applicable_check is None
                else context.applicable_check.semantic_withheld_item_ids
            )
        ),
        semantic_redacted_values=(
            ()
            if context.applicable_check is None
            else context.applicable_check.semantic_redacted_values
        ),
    )
