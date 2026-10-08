"""Pure canonical receipt assembly from one complete frozen application context."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from enum import Enum
from typing import Final, Literal, cast

from yoetz.domain.check_totals import render_check_totals
from yoetz.domain.events import (
    AcceptedEvent,
    CheckRecordedPayload,
    ClaimKind,
    ClaimRecordedPayloadV1_1,
    LedgerRecord,
    NoObligationsReason,
    ObligationChangeKind,
    ObligationStatus,
    ResponseRecordedPayload,
    is_lineage_service_stamped,
    is_observation_authored,
)
from yoetz.domain.findings import (
    FINDING_KIND_TRAITS,
    CheckVerdict,
    Finding,
    FindingOrigin,
    ResponseDisposition,
    SemanticProvenance,
    rank_key,
)
from yoetz.domain.receipts import (
    CHECK_CURRENT_AS_OF_EARLIER_FRONTIER_GAP,
    CHECK_TIME_CHANGE_RESOLUTION_UNVERIFIED_GAP,
    COMPLETION_CLAIM_OUTSIDE_PLAN_GAP,
    COMPLETION_PLAN_NOT_CLAIMED_GAP,
    COMPLETION_SCOPE_DECLARED_NONE_GAP,
    COMPLETION_SCOPE_UNDECLARED_GAP,
    OPTIONAL_SEMANTIC_REVIEW_REGISTRATION_DRIFT_GAP,
    PREEXISTING_TEST_INFORMATIONAL_GAPS,
    SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP,
    SEMANTIC_REVIEW_NOT_CONFIGURED_GAP,
    SEMANTIC_REVIEW_NOT_REQUESTED_GAP,
    SEMANTIC_REVIEW_SKIPPED_INSUFFICIENT_PACKET_GAP,
    ReceiptChildFinding,
    ReceiptChildOutcome,
    ReceiptChildren,
    ReceiptConclusion,
    ReceiptDisclosure,
    ReceiptDocument,
    ReceiptDuplicateLink,
    ReceiptGap,
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
from yoetz.domain.review_input_render import (
    render_review_input_manifest_compat_line,
    render_review_input_manifest_coverage_note,
)
from yoetz.domain.task_statement import (
    TASK_STATEMENT_NOT_AUTHORIZED_GAP,
    TASK_STATEMENT_NOT_SUPPLIED_GAP,
    TASK_STATEMENT_UNAVAILABLE_GAP,
    TaskStatementSource,
    current_task_statement,
    may_carry_task_statement,
    task_statement_gap_detail,
)
from yoetz.domain.values import (
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
from yoetz.kernel.claims import (
    claim_discloses_result,
    effective_claim_items,
    result_is_relevant_to_claim,
)
from yoetz.kernel.closure_readiness import premise_disputed_finding_ids
from yoetz.kernel.command_attempts import command_attempts
from yoetz.kernel.completion_scope import (
    SCOPE_REPAIR,
    completion_scope_differences,
)
from yoetz.kernel.deterministic_checks import (
    CALLER_DIGEST_PROVENANCE_GAPS,
    CaseAvailabilityFacts,
    CaseGap,
)
from yoetz.kernel.deterministic_scope import (
    CLEAN_COMPATIBLE_GAPS,
    HOST_OBSERVATION_GUARDED_GAPS,
)
from yoetz.kernel.finding_resolution import (
    finding_resolution_explanation,
    issue_key,
    unverified_resolution_finding_ids,
)
from yoetz.kernel.lineage import LineageEvaluation, LineageRollupState
from yoetz.kernel.observed_failures import (
    ObservedFailureState,
    observed_event_ids_from_records,
    observed_failure_states,
)
from yoetz.kernel.plan_scope import CurrentPlanScope, current_plan_scope
from yoetz.kernel.projections import ObligationProjectionRecord, ProjectionRecord, ProjectionState
from yoetz.kernel.reducers import is_material_event_family
from yoetz.kernel.task_facts import (
    acknowledged_obligation_ids,
    disclosure_declarations,
)
from yoetz.protocol.coverage import LEDGER_FRESHNESS_ORDER, Coverage, PublicationChannel, weakest
from yoetz.protocol.models import ReceiptInclude, ReceiptRedactionProfile, SemanticStatus

__all__ = [
    "CheckSuffixClass",
    "ReceiptBuildContext",
    "ReceiptFindingState",
    "build_receipt",
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
    # Issue #996: the earlier finding a holding ``duplicate_of`` link names. The flags above are
    # then the ones derived from it (``finding_todo``); the link is disclosed by ids.
    duplicate_of_finding_id: FindingId | None = None

    def __post_init__(self) -> None:
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
            or self.resolved
            + self.acknowledged_not_done
            + self.rejection_accepted
            + self.self_verified
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
    if len(selected) > 100:
        raise ValueError(_CONTEXT_INVALID)

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
    if len(refs) > 100:
        raise ValueError(_CONTEXT_INVALID)
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
    if len(refs) > 100:
        raise ValueError(_CONTEXT_INVALID)
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
    if len(values) > 100:
        raise ValueError(_CONTEXT_INVALID)
    return tuple(values)


_UNVERIFIED_RESOLUTION_LISTED: Final = 16


def _check_change_gap_text(context: ReceiptBuildContext, code: str) -> str | None:
    """The fixed sentence for a check-time code; for the legacy-resolution disclosure (R945-02),
    also the affected resolved findings, at most 16 by id and the rest as a count."""

    sentence = check_time_change_gap_sentence(code)
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


def _select_gaps(
    context: ReceiptBuildContext,
    historical: Mapping[str, Frontier] | None = None,
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
    if len(values) > 64:
        raise ValueError(_CONTEXT_INVALID)
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


def _receipt_children(evaluation: LineageEvaluation | None) -> ReceiptChildren:
    """Project the pure lineage evaluation into the receipt's bounded child section."""

    if evaluation is None:
        return ReceiptChildren()
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
    return ReceiptChildren(tuple(children))


def route_did_not_require_review(check: CheckRecordedPayload | None) -> bool:
    """True when ``check`` recorded a route that did not require AI-powered review (#986).

    Only an explicit ``semantic_route_required: false`` on a local-only check (``not_requested``)
    qualifies; an absent field is the safe default and keeps the missing review blocking.
    """

    return (
        check is not None
        and check.semantic_route_required is False
        and check.semantic_status is SemanticStatus.NOT_REQUESTED
        and SEMANTIC_REVIEW_NOT_REQUESTED_GAP in check.coverage.known_gaps
    )


def _conclusion(
    context: ReceiptBuildContext,
    unresolved_actionable: tuple[Finding, ...],
    *,
    self_verified: bool = False,
    obligations_not_done: bool = False,
    historical_codes: frozenset[str] = frozenset(),
) -> ReceiptConclusion:
    # One clean-compatible list for the receipt and the scoped deterministic verdict (#986).
    advisory_gaps = CLEAN_COMPATIBLE_GAPS
    # Issue #1017: a gap a later check cleared is history; only live gaps bound the conclusion.
    live_codes = set(context.coverage.known_gaps) - historical_codes
    if _COMPLETION_SCOPE_GAPS & live_codes:
        # These two closed gaps bound completion itself. Findings remain visible and actionable,
        # but they cannot make an empty completion scope read as sufficiently covered.
        return ReceiptConclusion.INSUFFICIENT_COVERAGE
    if unresolved_actionable or (
        context.lineage is not None and context.lineage.actionable_finding_ids
    ):
        return ReceiptConclusion.UNRESOLVED_FINDINGS_REMAIN
    if self_verified:
        # Issue #984 (ADR-034): only the agent verified these repairs; Yoetz could not prove
        # them, so the receipt is at best ``insufficient_coverage``, never clean.
        return ReceiptConclusion.INSUFFICIENT_COVERAGE
    if obligations_not_done:
        # Issue #997 (ADR-032 slice C): the agent acknowledged an obligation as not done, so the
        # declared scope is not complete; the receipt never reads clean.
        return ReceiptConclusion.INSUFFICIENT_COVERAGE
    if context.lineage is not None and context.lineage.blocks_clean_completion:
        return ReceiptConclusion.INSUFFICIENT_COVERAGE
    check = context.applicable_check
    if check is None:
        return ReceiptConclusion.INSUFFICIENT_COVERAGE
    if check.suppressed_count > 0:
        return ReceiptConclusion.INSUFFICIENT_COVERAGE
    if check.verdict in {
        CheckVerdict.INSUFFICIENT_COVERAGE,
        CheckVerdict.INCOMPLETE_CHECK,
    }:
        return ReceiptConclusion.INSUFFICIENT_COVERAGE
    if check.verdict is CheckVerdict.ACTION_REQUIRED:
        raise ValueError(_CONTEXT_INVALID)
    # A pack that ran to completion, or that had nothing to judge on the whole case
    # (``skipped/not_applicable``: no root of its kind exists, e.g. the coordination pack on a
    # single-agent run), leaves nothing unexamined (#986). ``scope_excluded`` (a scoped check
    # left roots of the pack unexamined) and ``material_unavailable`` (its roots were
    # unreadable) are real coverage loss and stay incomplete, as does ``failed``.
    executions_complete = all(
        (execution.outcome == "run" and execution.reason == "completed")
        or (execution.outcome == "skipped" and execution.reason == "not_applicable")
        for execution in check.policy_executions
    )
    # A host-observation gap is advisory only when the applicable check itself carried it: that
    # check reached its clean verdict only after its command counters showed no unknown or live
    # failed outcome. One that arrived after the check was never so guarded (#986).
    advisory_gaps = advisory_gaps - (HOST_OBSERVATION_GUARDED_GAPS - set(check.coverage.known_gaps))
    if route_did_not_require_review(check):
        # Issue #986 (owner decision E2, "record route; don't block"): the applicable check
        # recorded that its route did not require AI-powered review, so the missing review is a
        # disclosure. A check without the field (older builds, or a route that required review)
        # keeps it blocking.
        advisory_gaps = advisory_gaps | {SEMANTIC_REVIEW_NOT_REQUESTED_GAP}
    if (
        not executions_complete
        or any(
            gap.code not in advisory_gaps
            for gap in context.gaps
            if gap.code not in historical_codes
        )
        or (live_codes - advisory_gaps)
    ):
        return ReceiptConclusion.INSUFFICIENT_COVERAGE
    return ReceiptConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS


def _count_phrase(count: int, singular: str, plural: str) -> str:
    if count == 0:
        return f"no {plural}"
    if count == 1:
        return f"one {singular}"
    return f"{count} {plural}"


def _resolved_history_sentence(resolved_count: int) -> str:
    """Name resolved historical findings apart from current ones and from coverage gaps.

    A resolved finding is not erased and is not a limitation: it fired, the record was repaired,
    and a later qualifying check found the same issue absent. Saying so beside the current count
    is what lets a reader tell "was fixed" from "still open" without a per-finding flag, which the
    frozen receipt document does not carry.
    """

    if resolved_count == 0:
        return ""
    phrase = _count_phrase(resolved_count, "earlier finding was", "earlier findings were")
    return (
        f" {phrase[:1].upper() + phrase[1:]} resolved by a later qualifying check and "
        "remain visible as history."
        if resolved_count > 1
        else f" {phrase[:1].upper() + phrase[1:]} resolved by a later qualifying check and "
        "remains visible as history."
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
    """Count cited evidence items whose caller-asserted digest Yoetz did not verify.

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
    the receipt must still say that Yoetz did not verify those bytes. The retention clause keeps
    digest-only items (bytes never retained) apart from withheld items (the publisher withheld
    the bytes), because the two differ in what the owner can recover. Nothing an agent publishes
    changes the recorded provenance, so the sentence names no remedy. Without a per-item root the
    code comes only from recorded check or finding coverage; the sentence then describes that
    recorded limitation instead of implying currently cited items, and makes no permanence claim
    because a later check of the current record may no longer carry it.
    """

    if counts.total == 0:
        return (
            "Recorded check or finding coverage names caller-asserted digests that Yoetz did not "
            "verify; no currently cited evidence item carries one."
        )
    if counts.total == 1:
        subject = "One cited evidence item carries a caller-asserted digest"
    else:
        subject = f"{counts.total} cited evidence items carry caller-asserted digests"
    return (
        f"{subject} that Yoetz did not verify: {_caller_digest_retention_clause(counts)}. "
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
    later_material = tuple(
        record
        for record in context.records
        if is_material_event_family(record.schema.name)
        and record.ledger.ingestion_sequence > check_record.ledger.ingestion_sequence
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
            f"A check is recorded at {tested}, but material work was published after it, so "
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

    from yoetz.domain.observation_budget import AdmissionLossCause

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
    semantic_endpoint_sentence: str = "",
    semantic_usage_sentence: str = "",
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
    check_change_gap_texts: Mapping[str, str] | None = None,
    review_input_manifest: object | None = None,
    missing_for_assessment: object = (),
    check_totals_text: str = "",
    acknowledged_obligations: frozenset[str] = frozenset(),
    review_not_required: bool = False,
    historical_gap_codes: frozenset[str] = frozenset(),
) -> tuple[ReceiptSection, ...]:
    # Issue #1017: the limitations section lists live gaps only; the human renderings list the
    # historical ones (a later check cleared them) in their own section from the gap rows.
    gap_codes = tuple(code for code in coverage.known_gaps if code not in historical_gap_codes)
    gap_texts = check_change_gap_texts or {}
    bodies: dict[ReceiptSectionKey, str] = {}
    items: dict[ReceiptSectionKey, tuple[str, ...]] = {}
    resolved_sentence = _resolved_history_sentence(len(resolved_finding_ids))

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
            f"{phrase[:1].upper() + phrase[1:]} remain unresolved at frontier {frontier.sequence}."
            + resolved_sentence
        )
    if check_totals_text:
        bodies[ReceiptSectionKey.SUMMARY] += " " + check_totals_text
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

    actionable_count = unresolved_actionable_count
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

    claim_phrase = _count_phrase(len(claim_refs), "claim reference", "claim references")
    evidence_phrase = _count_phrase(len(evidence_refs), "evidence reference", "evidence references")
    bodies[ReceiptSectionKey.EVIDENCE_AND_CLAIM_BASIS] = (
        f"The receipt retains {claim_phrase} and {evidence_phrase}."
    )
    items[ReceiptSectionKey.EVIDENCE_AND_CLAIM_BASIS] = (*claim_refs, *evidence_refs)

    if attempt_explanations:
        bodies[ReceiptSectionKey.EVIDENCE_AND_CLAIM_BASIS] += " " + " ".join(attempt_explanations)

    if gap_codes:
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
        )
        if check_sentence:
            gap_body = f"{check_sentence} Coverage is limited by: {', '.join(gap_codes)}."
        elif not_requested and SEMANTIC_REVIEW_SKIPPED_INSUFFICIENT_PACKET_GAP in gap_codes:
            gap_body = (
                "AI-powered review was skipped: the reviewer twice in a row, or four times since "
                "the last assessed review, could not assess the review packet (a Yoetz limit). "
                f"Coverage is limited by: {', '.join(gap_codes)}."
            )
        elif not_requested:
            gap_body = (
                "AI-powered review was not requested (local-only check). "
                f"Coverage is limited by: {', '.join(gap_codes)}."
            )
        elif not_run:
            gap_body = (
                "AI-powered relevance review was not run. "
                f"Coverage is limited by: {', '.join(gap_codes)}."
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
                "re-run `yoetz integrate codex mcp preview` and "
                "`yoetz integrate codex mcp install --route-profile policy`, then start a "
                "fresh Codex process. "
                f"Coverage is limited by: {', '.join(gap_codes)}."
            )
        else:
            gap_body = f"Coverage is limited by: {', '.join(gap_codes)}."
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

    policy_rows = "; ".join(
        f"{entry.policy_id} {entry.policy_version}" for entry in versions.policy_versions
    )
    bodies[ReceiptSectionKey.VERSION_AND_POLICY_IDENTITY] = (
        f"Engine {versions.engine_version}; protocol {versions.protocol_version}; {policy_rows}."
        + semantic_endpoint_sentence
        + semantic_usage_sentence
    )
    items[ReceiptSectionKey.VERSION_AND_POLICY_IDENTITY] = ()

    return tuple(
        ReceiptSection(
            key=key,
            title=_SECTION_TITLES[key],
            body=bodies[key],
            items=items[key],
            coverage_note=(
                review_input_coverage_note
                if key is ReceiptSectionKey.LIMITATIONS_AND_COVERAGE
                else None
            ),
        )
        for key in _SECTION_KEYS[include]
    )


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
    # A ``self_verified`` row (issue #984) likewise stops counting as agent work only where its
    # own section discloses it; it still keeps the conclusion from reading clean.
    unresolved_actionable = tuple(
        finding
        for finding in findings
        if not states_by_id[finding.finding_id].resolved
        and not (settles_rejections and states_by_id[finding.finding_id].rejection_accepted)
        and not (settles_rejections and states_by_id[finding.finding_id].self_verified)
        and FINDING_KIND_TRAITS[finding.kind][1]
    )
    # Issue #997: obligations the agent acknowledged as not done (ADR-032 slice C).
    acknowledged_obligations = tuple(
        sorted(acknowledged_obligation_ids(context.projection), key=_ascii_key)
    )[:100]
    # Issue #1017: only the 1.3.0 artifact can mark a gap historical; earlier artifacts keep
    # every gap live, exactly as they were issued.
    historical = dict(context.historical_gaps) if settles_rejections else {}
    conclusion = _conclusion(
        context,
        unresolved_actionable,
        self_verified=any(states_by_id[finding.finding_id].self_verified for finding in findings),
        obligations_not_done=bool(acknowledged_obligations),
        historical_codes=frozenset(historical),
    )
    obligations = _select_obligations(context, findings)
    responses = _select_responses(context, frozenset(finding.finding_id for finding in findings))
    claim_refs = _select_claim_refs(context, findings)
    evidence_refs = _select_evidence_refs(context, claim_refs, obligations, responses)
    gaps = _select_gaps(context, historical)
    children = _receipt_children(context.lineage)
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
    sections = _sections(
        check_change_gap_texts={
            code: text
            for code in context.coverage.known_gaps
            if code not in historical
            and (text := _check_change_gap_text(context, code)) is not None
        },
        include=include,
        conclusion=conclusion,
        frontier=context.subject_frontier,
        versions=versions,
        findings=retained_findings,
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
        semantic_endpoint_sentence=_semantic_endpoint_sentence(context.applicable_check),
        review_not_required=route_did_not_require_review(context.applicable_check),
        task_statement_source_sentence=_task_statement_source_sentence(
            context.applicable_check, context.records
        ),
        semantic_usage_sentence=_semantic_usage_sentence(
            None
            if context.applicable_check is None
            else context.applicable_check.semantic_provenance
        ),
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
        acknowledged_not_done_finding_ids=acknowledged_not_done_ids,
        rejection_accepted_finding_ids=rejection_accepted_ids,
        self_verified_finding_ids=self_verified_ids,
        duplicate_finding_links=duplicate_links,
        # Issue #984 (D7a): the acknowledged findings whose premise the reviewer disputes.
        premise_disputed_finding_ids=tuple(
            item
            for item in premise_disputed_finding_ids(context.projection)
            if item in acknowledged_not_done_ids
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
