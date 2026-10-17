"""Canonical receipt builder context, conclusion, section, and profile tests."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from types import SimpleNamespace
from typing import Any, cast

import pytest

from finishup.domain.check_totals import CHECK_TOTAL_KEYS, render_check_totals
from finishup.domain.events import (
    CheckMode,
    CheckRecordedPayload,
    LedgerRecord,
    MissingForAssessmentItem,
    NoObligationsReason,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    PolicyVersion,
    ResponseRecordedPayload,
    encode_payload,
)
from finishup.domain.findings import (
    FINDING_KIND_TRAITS,
    CheckVerdict,
    Finding,
    FindingKind,
    FindingOrigin,
    ResponseDisposition,
    RuntimeAttemptEvidence,
    RuntimeTokenUsage,
    SemanticDispatchKind,
    SemanticProvenance,
    semantic_provenance_to_json,
)
from finishup.domain.receipts import (
    CHECK_CURRENT_AS_OF_EARLIER_FRONTIER_GAP,
    COMPLETION_CLAIM_OUTSIDE_PLAN_GAP,
    COMPLETION_SCOPE_DECLARED_NONE_GAP,
    COMPLETION_SCOPE_UNDECLARED_GAP,
    SEMANTIC_REDACTED_VALUES_AGENT_LINE,
    PolicyVersionEntry,
    ReceiptConclusion,
    ReceiptDocument,
    ReceiptObligationStatus,
    ReceiptRedactionCategory,
    ReceiptRedactionReason,
    ReceiptSectionKey,
    ReceiptVersionSlice,
    SchemaVersionEntry,
    receipt_document_from_json,
    receipt_document_to_json,
    render_receipt_compact,
    render_receipt_human,
    resolved_finding_ids_for_render,
    unresolved_findings_for_render,
)
from finishup.domain.values import (
    ActorType,
    EventId,
    FindingId,
    Frontier,
    JsonObject,
    event_id,
    finding_id,
    freeze_json,
    obligation_id,
    receipt_id,
    result_id,
    session_id,
    task_id,
    timestamp_from_string,
)
from finishup.kernel.deterministic_checks import CaseAvailabilityFacts, CaseGap
from finishup.kernel.projections import (
    FindingProjectionRecord,
    LatestTestedState,
    ObligationProjectionRecord,
    PlanProjectionRecord,
    ProjectionRecord,
    ProjectionState,
    empty_projection_state,
)
from finishup.kernel.receipt_builder import (
    CheckSuffixClass,
    ReceiptBuildContext,
    ReceiptFindingState,
    build_receipt,
)
from finishup.ports.semantic import SamplingParams
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)
from finishup.protocol.models import (
    CheckPolicyExecutionModel,
    CheckScopeModel,
    ReceiptInclude,
    ReceiptRedactionProfile,
    SemanticReason,
    SemanticStatus,
)
from finishup.protocol.redacted_values import SemanticRedactedValue

_DIGEST = "sha256:" + "1" * 64
_HEAD = "sha256:" + "2" * 64
_FINDING_ID = finding_id("fnd_00000000-0000-4000-8000-000000000001")
_SOURCE_EVENT_ID = event_id("evt_00000000-0000-4000-8000-000000000001")
_CHECK_EVENT_ID = event_id("evt_00000000-0000-4000-8000-000000000002")
_FRONTIER = Frontier(2, _HEAD)


def _coverage(*, gaps: tuple[str, ...] = ()) -> Coverage:
    return Coverage(
        publication_channels=(PublicationChannel.ENGINE_DERIVED,),
        authorship_assurance=AuthorshipAssurance.SERVICE_AUTHENTICATED,
        artifact_observation=ArtifactObservation.ARTIFACT_VERIFIED,
        evidence_immutability=EvidenceImmutability.IMMUTABLE_SNAPSHOT,
        ledger_freshness=LedgerFreshness.CURRENT if not gaps else LedgerFreshness.PARTIAL,
        check_types=(CheckType.DETERMINISTIC,),
        known_gaps=gaps,
    )


def _finding() -> Finding:
    kind = FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS
    return Finding(
        finding_id=_FINDING_ID,
        kind=kind,
        origin=FindingOrigin.DETERMINISTIC,
        priority=FINDING_KIND_TRAITS[kind][0],
        summary="An obligation remains open.",
        detail="Resolve the recorded obligation.",
        subject_refs=(obligation_id("obl_00000000-0000-4000-8000-000000000001"),),
        policy_id="work-integrity",
        policy_version="0.1.0",
        subject_frontier=Frontier(1, _DIGEST),
        coverage=_coverage(),
    )


def _check(
    verdict: CheckVerdict,
    coverage: Coverage,
    *,
    returned: tuple[FindingId, ...] = (),
    suppressed: int = 0,
    semantic_provenance: SemanticProvenance | None = None,
    semantic_conclusion: str | None = None,
    missing_for_assessment: tuple[MissingForAssessmentItem, ...] = (),
    review_input_manifest: dict[str, object] | None = None,
    semantic_withheld_item_ids: tuple[str, ...] = (),
    totals: JsonObject | None = None,
    semantic_redacted_values: tuple[SemanticRedactedValue, ...] = (),
) -> CheckRecordedPayload:
    return CheckRecordedPayload(
        mode=(
            CheckMode.DETERMINISTIC_ONLY
            if semantic_provenance is None
            else CheckMode.SEMANTIC_IF_CONFIGURED
        ),
        policies=(PolicyVersion("work-integrity", "0.1.0"),),
        scope=CheckScopeModel(claim_ids=(), obligation_ids=()),
        policy_executions=(
            CheckPolicyExecutionModel(
                policy_id="work-integrity",
                policy_version="0.1.0",
                outcome="run",
                reason="completed",
            ),
        ),
        subject_frontier=_FRONTIER,
        verdict=verdict,
        returned_finding_ids=returned,
        suppressed_count=suppressed,
        coverage=coverage,
        semantic_status=(
            SemanticStatus.NOT_REQUESTED
            if semantic_provenance is None
            else semantic_provenance.status
        ),
        semantic_reason=(
            SemanticReason.DETERMINISTIC_MODE
            if semantic_provenance is None
            else semantic_provenance.reason
        ),
        semantic_provenance=semantic_provenance,
        semantic_conclusion=semantic_conclusion,
        missing_for_assessment=missing_for_assessment,
        review_input_manifest=(
            None
            if review_input_manifest is None
            else cast(JsonObject, freeze_json(review_input_manifest))
        ),
        engine_version="0.1.0",
        projection_version="yoetz/0.1.0",
        semantic_withheld_item_ids=semantic_withheld_item_ids,
        totals=totals,
        semantic_redacted_values=semantic_redacted_values,
    )


def _totals() -> JsonObject:
    return cast(
        JsonObject,
        freeze_json(
            {group: {key: "1" for key in keys} for group, keys in CHECK_TOTAL_KEYS.items()}
        ),
    )


def _projection(
    *,
    finding: Finding | None = None,
    response: ResponseRecordedPayload | None = None,
    check: CheckRecordedPayload | None = None,
    coverage_gaps: tuple[str, ...] = (),
    plan: PlanPublishedPayload | None = None,
    obligation: ObligationPublishedPayload | None = None,
    plan_redacted: bool = False,
    obligation_redacted: bool = False,
) -> object:
    findings: dict[object, object] = {}
    if finding is not None:
        findings[finding.finding_id] = FindingProjectionRecord(
            payload=finding,
            payload_digest=canonical_digest(encode_payload(finding)),
            redacted=False,
            source_event_id=_SOURCE_EVENT_ID,
            source_frontier=1,
        )
    responses: dict[object, object] = {}
    if response is not None:
        responses[response.finding_id] = ProjectionRecord(
            payload=response,
            payload_digest=canonical_digest(encode_payload(response)),
            redacted=False,
            source_event_id=event_id("evt_00000000-0000-4000-8000-000000000003"),
            source_frontier=2,
        )
    latest = None
    if check is not None:
        latest = LatestTestedState(
            source_check_event_id=_CHECK_EVENT_ID,
            subject_frontier=check.subject_frontier,
            verdict=check.verdict,
            returned_finding_ids=check.returned_finding_ids,
            suppressed_count=check.suppressed_count,
            coverage=check.coverage,
        )
    plans = {}
    if plan is not None:
        plans[plan.plan_version] = PlanProjectionRecord(
            payload=None if plan_redacted else plan,
            payload_digest=canonical_digest(encode_payload(plan)),
            redacted=plan_redacted,
            source_event_id=event_id("evt_00000000-0000-4000-8000-000000000010"),
            source_frontier=1,
        )
    obligations = {}
    if obligation is not None:
        obligations[obligation.obligation_id] = ObligationProjectionRecord(
            payload=None if obligation_redacted else obligation,
            payload_digest=canonical_digest(encode_payload(obligation)),
            redacted=obligation_redacted,
            source_event_id=event_id("evt_00000000-0000-4000-8000-000000000011"),
            source_frontier=1,
        )
    return replace(
        empty_projection_state(),
        frontier=2,
        head_digest=_HEAD,
        plans=plans,
        obligations=obligations,
        findings=findings,
        responses=responses,
        latest_tested_state=latest,
        freshness=LedgerFreshness.CURRENT,
        coverage_gaps=coverage_gaps,
    )


def _versions() -> ReceiptVersionSlice:
    return ReceiptVersionSlice(
        package_name="finishup",
        package_version="0.1.0",
        protocol_version="0.1",
        engine_version="0.1.0",
        projection_version="yoetz/0.1.0",
        object_format_version="yoetz-object/1",
        catalog_schema_version="1",
        bundle_schema_version="1",
        policy_versions=(
            PolicyVersionEntry("research-evidence", "0.1.0"),
            PolicyVersionEntry("work-integrity", "0.1.0"),
        ),
        schema_versions=(SchemaVersionEntry("receipts/receipt-document", "1.0.0"),),
        resource_manifest_digest="sha256:" + "9" * 64,
    )


def _context(
    *,
    finding: Finding | None = None,
    resolved: bool = False,
    response: ResponseRecordedPayload | None = None,
    check: CheckRecordedPayload | None = None,
    coverage: Coverage | None = None,
    gaps: tuple[CaseGap, ...] = (),
    plan: PlanPublishedPayload | None = None,
    obligation: ObligationPublishedPayload | None = None,
    plan_redacted: bool = False,
    obligation_redacted: bool = False,
) -> ReceiptBuildContext:
    actual_coverage = _coverage() if coverage is None else coverage
    projection = _projection(
        finding=finding,
        response=response,
        check=check,
        coverage_gaps=(),
        plan=plan,
        obligation=obligation,
        plan_redacted=plan_redacted,
        obligation_redacted=obligation_redacted,
    )
    return ReceiptBuildContext(
        projection=cast("ProjectionState", projection),
        subject_frontier=_FRONTIER,
        availability=CaseAvailabilityFacts(),
        coverage=actual_coverage,
        gaps=gaps,
        finding_states=(
            () if finding is None else (ReceiptFindingState(finding.finding_id, resolved=resolved),)
        ),
        applicable_check=check,
    )


def _build(
    context: ReceiptBuildContext,
    *,
    profile: ReceiptRedactionProfile = ReceiptRedactionProfile.FULL_LOCAL,
    include: ReceiptInclude = ReceiptInclude.FULL,
):
    return build_receipt(
        context,
        receipt_id("rcp_00000000-0000-4000-8000-000000000001"),
        task_id("tsk_00000000-0000-4000-8000-000000000001"),
        session_id("ses_00000000-0000-4000-8000-000000000001"),
        timestamp_from_string("2026-07-19T00:00:00.000Z"),
        _versions(),
        profile,
        include,
    )


def test_frontier_mismatch_is_rejected() -> None:
    coverage = _coverage()
    check = _check(CheckVerdict.NO_ISSUE_DETECTED, coverage)
    projection = cast("ProjectionState", _projection(check=check))
    with pytest.raises(ValueError, match="receipt_build_context_invalid"):
        ReceiptBuildContext(
            projection=projection,
            subject_frontier=Frontier(1, _DIGEST),
            availability=CaseAvailabilityFacts(),
            coverage=coverage,
            gaps=(),
            finding_states=(),
            applicable_check=check,
        )


def test_conclusion_selection_matches_state_strength() -> None:
    finding = _finding()
    action_check = _check(CheckVerdict.ACTION_REQUIRED, _coverage(), returned=(_FINDING_ID,))
    assert _build(_context(finding=finding, check=action_check)).conclusion is (
        ReceiptConclusion.UNRESOLVED_FINDINGS_REMAIN
    )


def test_check_totals_are_carried_in_json_and_human_receipt_summary() -> None:
    totals = _totals()
    receipt = _build(
        _context(
            check=_check(CheckVerdict.NO_ISSUE_DETECTED, _coverage(), totals=totals),
        )
    )
    rendered_totals = render_check_totals(totals)
    summary = next(
        section for section in receipt.sections if section.key is ReceiptSectionKey.SUMMARY
    )
    assert rendered_totals in summary.body
    assert rendered_totals in render_receipt_human(receipt, markdown=True)
    assert rendered_totals in render_receipt_human(receipt, markdown=False)
    encoded = receipt_document_to_json(receipt)
    sections = cast(list[dict[str, object]], encoded["sections"])
    assert rendered_totals in cast(str, sections[0]["body"])

    clear_check = _check(CheckVerdict.NO_ISSUE_DETECTED, _coverage())
    assert _build(_context(check=clear_check)).conclusion is (
        ReceiptConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS
    )

    gap = CaseGap("check_not_recorded", "check_not_recorded", ())
    weak = _coverage(gaps=("check_not_recorded",))
    assert _build(_context(coverage=weak, gaps=(gap,))).conclusion is (
        ReceiptConclusion.INSUFFICIENT_COVERAGE
    )


def test_digest_provenance_limitation_is_retained_in_receipt() -> None:
    code = "evidence_content_digest_only"
    gap = CaseGap(f"{code}:{_SOURCE_EVENT_ID}", code, (_SOURCE_EVENT_ID,))
    coverage = _coverage(gaps=(code,))
    check = _check(CheckVerdict.NO_ISSUE_DETECTED, coverage)
    receipt = _build(_context(coverage=coverage, gaps=(gap,), check=check))
    assert receipt.conclusion is ReceiptConclusion.INSUFFICIENT_COVERAGE
    assert receipt.coverage.known_gaps == (code,)
    assert tuple(item.code for item in receipt.gaps) == (code,)
    limitations = next(
        section.body
        for section in receipt.sections
        if section.key is ReceiptSectionKey.LIMITATIONS_AND_COVERAGE
    )
    assert (
        "One cited evidence item carries a caller-asserted digest that FinishUP did not verify"
        in (limitations)
    )


_WITHHELD_EVENT_ID = event_id("evt_00000000-0000-4000-8000-000000000009")
_SECOND_DIGEST_EVENT_ID = event_id("evt_00000000-0000-4000-8000-00000000000a")
_DIGEST_ONLY_CLAUSE = "the digest was recorded but the bytes were not retained"
_WITHHELD_CLAUSE = "the publisher recorded the bytes as withheld"


def _digest_gap(code: str, root: EventId) -> CaseGap:
    return CaseGap(f"{code}:{root}", code, (root,))


@pytest.mark.parametrize(
    ("gaps", "expected", "per_item", "absent"),
    (
        pytest.param(
            (
                _digest_gap("evidence_content_digest_only", _SOURCE_EVENT_ID),
                _digest_gap("evidence_content_withheld", _WITHHELD_EVENT_ID),
            ),
            "2 cited evidence items carry caller-asserted digests that FinishUP did not verify: "
            f"1 is digest-only ({_DIGEST_ONLY_CLAUSE}) and 1 is withheld ({_WITHHELD_CLAUSE}).",
            True,
            (),
            id="mixed-retention",
        ),
        pytest.param(
            (
                _digest_gap("evidence_content_digest_only", _SOURCE_EVENT_ID),
                _digest_gap("evidence_content_digest_only", _SECOND_DIGEST_EVENT_ID),
            ),
            "2 cited evidence items carry caller-asserted digests that FinishUP did not verify: "
            f"{_DIGEST_ONLY_CLAUSE}.",
            True,
            (_WITHHELD_CLAUSE, "withheld"),
            id="digest-only",
        ),
        pytest.param(
            (_digest_gap("evidence_content_withheld", _WITHHELD_EVENT_ID),),
            "One cited evidence item carries a caller-asserted digest that FinishUP did not "
            f"verify: {_WITHHELD_CLAUSE}.",
            True,
            ("not retained", "digest-only"),
            id="withheld-only",
        ),
        pytest.param(
            (
                CaseGap(
                    "check_coverage:evidence_content_digest_only",
                    "evidence_content_digest_only",
                    (),
                ),
            ),
            "Recorded check or finding coverage names caller-asserted digests that FinishUP did not "
            "verify; no currently cited evidence item carries one.",
            False,
            (),
            id="check-coverage-only",
        ),
    ),
)
def test_caller_digest_label_is_named_once_with_its_count(
    gaps: tuple[CaseGap, ...], expected: str, per_item: bool, absent: tuple[str, ...]
) -> None:
    """Issue #912 fallback (a): the receipt, not a finding, discloses unverified caller digests.

    Without a per-item gap root the code comes only from recorded check or finding coverage, so
    the label describes that recorded limitation and never implies currently cited items or
    permanence (a later check of the current record may drop it). Digest-only and withheld items
    keep their distinct retention wording (review finding PR925-F3): a withheld item is never
    described as merely not retained, nor a digest-only item as withheld. Every format carries
    it.
    """

    codes = tuple(sorted({gap.code for gap in gaps}))
    coverage = _coverage(gaps=codes)
    ordered = tuple(sorted(gaps, key=lambda gap: gap.marker))
    receipt = _build(
        _context(
            coverage=coverage,
            gaps=ordered,
            check=_check(CheckVerdict.NO_ISSUE_DETECTED, coverage),
        )
    )
    limitations = next(
        section.body
        for section in receipt.sections
        if section.key is ReceiptSectionKey.LIMITATIONS_AND_COVERAGE
    )
    assert expected in limitations
    assert limitations.count("caller-asserted digest") == 1
    assert ("no response or recheck changes it" in limitations) is per_item
    if not per_item:
        assert "cited evidence items carry" not in limitations
        assert "Cited evidence carries" not in limitations
    assert "content-bearing" not in limitations
    wire = receipt_document_to_json(receipt)
    assert any(
        cast(dict[str, object], section)["body"] == limitations
        for section in cast(list[object], wire["sections"])
    )
    for fragment in absent:
        assert fragment not in limitations
    for markdown in (True, False):
        rendered = render_receipt_human(receipt, markdown=markdown)
        assert expected in rendered
        for fragment in absent:
            assert fragment not in rendered


def test_resolved_history_no_longer_lowers_receipt_coverage() -> None:
    """Issue #912: a resolved row stays listed as history but its coverage is not folded."""

    weaker = replace(_finding(), coverage=_coverage(gaps=("cursor_stale",)))
    check = _check(CheckVerdict.NO_ISSUE_DETECTED, _coverage())
    receipt = _build(_context(finding=weaker, resolved=True, check=check))
    assert receipt.coverage == _coverage()
    assert receipt.conclusion is ReceiptConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS
    assert tuple(finding.finding_id for finding in receipt.findings) == (_FINDING_ID,)
    summary = next(
        section for section in receipt.sections if section.key is ReceiptSectionKey.SUMMARY
    )
    assert summary.items == (_FINDING_ID,)
    assert "resolved by a later qualifying check" in summary.body

    # A current row must still bound the coverage the application supplies.
    with pytest.raises(ValueError, match="receipt_build_context_invalid"):
        _context(finding=weaker, resolved=False, check=check)


def test_suppressed_findings_block_clear_conclusion_until_fresh_check() -> None:
    capped = _check(CheckVerdict.NO_ISSUE_DETECTED, _coverage(), suppressed=2)
    receipt = _build(_context(check=capped))
    assert receipt.conclusion is ReceiptConclusion.INSUFFICIENT_COVERAGE
    assert receipt.suppressed_finding_count == 2
    fresh = _build(_context(check=_check(CheckVerdict.NO_ISSUE_DETECTED, _coverage())))
    assert fresh.conclusion is ReceiptConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS
    assert fresh.suppressed_finding_count == 0


def test_section_order_is_canonical() -> None:
    context = _context(check=_check(CheckVerdict.NO_ISSUE_DETECTED, _coverage()))
    expected = {
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
    for include, keys in expected.items():
        assert tuple(section.key for section in _build(context, include=include).sections) == keys


def test_redaction_profiles_change_canonical_bytes_without_changing_truth() -> None:
    finding = _finding()
    response = ResponseRecordedPayload(
        finding_id=finding.finding_id,
        finding_frontier=finding.subject_frontier,
        disposition=ResponseDisposition.REJECTED,
        reason="A protected rejection reason.",
    )
    check = _check(CheckVerdict.ACTION_REQUIRED, _coverage(), returned=(finding.finding_id,))
    context = _context(finding=finding, response=response, check=check)
    full = _build(context)
    shared = _build(context, profile=ReceiptRedactionProfile.REDACTED_SHARE)
    assert full.conclusion is shared.conclusion
    assert full.subject_frontier == shared.subject_frontier
    assert full.coverage == shared.coverage
    assert full.responses and not shared.responses
    assert shared.redactions == (
        next(
            row
            for row in shared.redactions
            if row.category is ReceiptRedactionCategory.FINDING_DETAIL
            and row.reason is ReceiptRedactionReason.POLICY_REDACTED
        ),
    )
    assert canonical_digest(freeze_json(receipt_document_to_json(full))) != canonical_digest(
        freeze_json(receipt_document_to_json(shared))
    )


def test_profile_by_include_matrix_is_exhaustive() -> None:
    context = _context(check=_check(CheckVerdict.NO_ISSUE_DETECTED, _coverage()))
    documents = {
        (profile, include): _build(context, profile=profile, include=include)
        for profile in ReceiptRedactionProfile
        for include in ReceiptInclude
    }
    assert len(documents) == 9
    for profile in ReceiptRedactionProfile:
        truth = [documents[(profile, include)] for include in ReceiptInclude]
        assert len({document.findings for document in truth}) == 1
        assert len({document.coverage for document in truth}) == 1
        assert len({tuple(gap.code for gap in document.gaps) for document in truth}) == 1


def test_context_requires_explicit_availability_and_applicable_check() -> None:
    coverage = _coverage()
    projection = cast("ProjectionState", _projection())
    with pytest.raises(ValueError, match="receipt_build_context_invalid"):
        ReceiptBuildContext(
            projection=projection,
            subject_frontier=_FRONTIER,
            availability=CaseAvailabilityFacts(),
            coverage=coverage,
            gaps=(),
            finding_states=(),
            applicable_check=None,
        )


def test_applicable_check_at_earlier_subject_frontier_builds() -> None:
    """Applicability follows the material state, not frontier equality: a check recorded at an
    earlier subject frontier still applies to this context. The builder trusts the application's
    applicability decision and never re-derives it."""

    coverage = _coverage()
    check = replace(
        _check(CheckVerdict.NO_ISSUE_DETECTED, coverage),
        subject_frontier=Frontier(1, _DIGEST),
    )
    receipt = _build(_context(check=check))
    assert receipt.conclusion is ReceiptConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS
    assert receipt.suppressed_finding_count == 0


def _earlier_frontier_limitations(check_suffix: CheckSuffixClass | None) -> tuple[str, str]:
    code = CHECK_CURRENT_AS_OF_EARLIER_FRONTIER_GAP
    coverage = _coverage(gaps=(code,))
    check = replace(
        _check(CheckVerdict.NO_ISSUE_DETECTED, coverage),
        subject_frontier=Frontier(1, _DIGEST),
    )
    context = replace(
        _context(coverage=coverage, gaps=(CaseGap(code, code, ()),), check=check),
        check_suffix=check_suffix,
    )
    receipt = _build(context)
    limitations = next(
        section.body
        for section in receipt.sections
        if section.key is ReceiptSectionKey.LIMITATIONS_AND_COVERAGE
    )
    return limitations, receipt.conclusion.value


@pytest.mark.parametrize(
    ("check_suffix", "conclusion"),
    [
        # Issue #1021 (tb4n2 P1-4a): only answers to the check's own findings followed it, so the
        # earlier-frontier note is a disclosure, not a coverage bound.
        (CheckSuffixClass.RESPONSES_ONLY, ReceiptConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS),
        (CheckSuffixClass.OBSERVATIONS_ONLY, ReceiptConclusion.INSUFFICIENT_COVERAGE),
        (CheckSuffixClass.MIXED, ReceiptConclusion.INSUFFICIENT_COVERAGE),
        (None, ReceiptConclusion.INSUFFICIENT_COVERAGE),
    ],
)
def test_a_responses_only_suffix_is_advisory_and_any_other_suffix_bounds(
    check_suffix: CheckSuffixClass | None, conclusion: ReceiptConclusion
) -> None:
    limitations, value = _earlier_frontier_limitations(check_suffix)
    assert value == conclusion.value
    # Always disclosed, whatever the conclusion.
    assert "Its verdict is current as of subject frontier 1, not frontier 2." in limitations


def test_check_current_as_of_earlier_frontier_names_the_tested_frontier() -> None:
    """The attributed-check gap must read as a qualification, never as a clean re-check: it names
    the frontier the verdict is current as of and still blocks the strong conclusion. With a
    response-only suffix it may say so (issue #657)."""

    limitations, _ = _earlier_frontier_limitations(CheckSuffixClass.RESPONSES_ONLY)
    assert "A check is recorded at subject frontier 1 and still contributes here" in limitations
    assert "only responses to the findings it returned were published after it" in limitations
    assert "Its verdict is current as of subject frontier 1, not frontier 2." in limitations
    assert "host observations" not in limitations


def test_check_current_as_of_earlier_frontier_names_observation_suffix() -> None:
    """Issue #657: finding-free host observations keep the check attributable through the same
    gap, and the explanation must say observations, never invent finding responses."""

    limitations, _ = _earlier_frontier_limitations(CheckSuffixClass.OBSERVATIONS_ONLY)
    assert "A check is recorded at subject frontier 1 and still contributes here" in limitations
    assert "finding-free host observations" in limitations
    assert "through frontier 2" in limitations
    assert "not evaluated by that check" in limitations
    assert "only responses to the findings it returned" not in limitations
    assert "Its verdict is current as of subject frontier 1, not frontier 2." in limitations
    assert "routine observation can advance the ledger again" in limitations
    assert "Ingestion order does not establish when observed work occurred." in limitations


def test_manifest_only_suffix_is_named_as_engine_derived_lineage() -> None:
    """A recorded child manifest is service lineage, not a host observation.

    The receipt must describe only the frozen parent records it received.  A lineage manifest
    after an attributable check therefore gets its own bounded wording and cannot be presented as
    a host-authored observation.
    """

    code = CHECK_CURRENT_AS_OF_EARLIER_FRONTIER_GAP
    coverage = _coverage(gaps=(code,))
    check = replace(
        _check(CheckVerdict.NO_ISSUE_DETECTED, coverage),
        subject_frontier=Frontier(1, _DIGEST),
    )
    check_record = SimpleNamespace(
        event_id=_CHECK_EVENT_ID,
        schema=SimpleNamespace(name="check_recorded"),
        ledger=SimpleNamespace(ingestion_sequence=2),
    )
    manifest_record = SimpleNamespace(
        event_id=event_id("evt_00000000-0000-4000-8000-000000000004"),
        schema=SimpleNamespace(name="child_dependencies_recorded"),
        author=SimpleNamespace(
            actor_id="yoetz:observation-coordinator",
            actor_type=ActorType.HARNESS,
            assurance=AuthorshipAssurance.HARNESS_OBSERVED,
        ),
        publication_channel=PublicationChannel.ENGINE_DERIVED,
        ledger=SimpleNamespace(ingestion_sequence=3),
    )
    context = replace(
        _context(coverage=coverage, gaps=(CaseGap(code, code, ()),), check=check),
        check_suffix=CheckSuffixClass.OBSERVATIONS_ONLY,
        records=cast(tuple[LedgerRecord, ...], (check_record, manifest_record)),
    )

    receipt = _build(context)
    limitations = next(
        section.body
        for section in receipt.sections
        if section.key is ReceiptSectionKey.LIMITATIONS_AND_COVERAGE
    )
    assert "service-generated child-dependency manifests" in limitations
    assert "finding-free host observations" not in limitations
    assert "not evaluated by that check" in limitations


def test_check_current_as_of_earlier_frontier_names_mixed_suffix() -> None:
    limitations, _ = _earlier_frontier_limitations(CheckSuffixClass.MIXED)
    assert "responses to the findings it returned and finding-free host observations" in (
        limitations
    )
    assert "only responses" not in limitations
    assert "Its verdict is current as of subject frontier 1, not frontier 2." in limitations


def test_check_current_as_of_earlier_frontier_without_suffix_class_stays_neutral() -> None:
    """An unclassified suffix gets neutral wording rather than a guessed event class."""

    limitations, _ = _earlier_frontier_limitations(None)
    assert "no cooperative material work superseded it through frontier 2" in limitations
    assert "only responses" not in limitations
    assert "host observations" not in limitations
    assert "Its verdict is current as of subject frontier 1, not frontier 2." in limitations


def test_check_suffix_class_requires_an_attributable_earlier_check() -> None:
    """The class describes what followed an attributable check; without the gap and check it
    describes nothing and the context is rejected."""

    coverage = _coverage()
    check = _check(CheckVerdict.NO_ISSUE_DETECTED, coverage)
    with pytest.raises(ValueError, match="receipt_build_context_invalid"):
        replace(_context(coverage=coverage, check=check), check_suffix=CheckSuffixClass.MIXED)
    with pytest.raises(ValueError, match="receipt_build_context_invalid"):
        replace(_context(), check_suffix=CheckSuffixClass.OBSERVATIONS_ONLY)


def test_check_current_as_of_earlier_frontier_without_a_check_is_rejected() -> None:
    """The gap qualifies a check that contributes; it can never stand in for an absent one."""

    code = CHECK_CURRENT_AS_OF_EARLIER_FRONTIER_GAP
    coverage = _coverage(gaps=(code, "check_not_recorded"))
    with pytest.raises(ValueError, match="receipt_build_context_invalid"):
        ReceiptBuildContext(
            projection=cast("ProjectionState", _projection()),
            subject_frontier=_FRONTIER,
            availability=CaseAvailabilityFacts(),
            coverage=coverage,
            gaps=(
                CaseGap(code, code, ()),
                CaseGap("check_not_recorded", "check_not_recorded", ()),
            ),
            finding_states=(),
            applicable_check=None,
        )


def test_applicable_check_ahead_of_context_is_rejected() -> None:
    coverage = _coverage()
    check = _check(CheckVerdict.NO_ISSUE_DETECTED, coverage)
    projection = cast("ProjectionState", _projection(check=check))
    ahead = replace(check, subject_frontier=Frontier(3, "sha256:" + "3" * 64))
    with pytest.raises(ValueError, match="receipt_build_context_invalid"):
        ReceiptBuildContext(
            projection=projection,
            subject_frontier=_FRONTIER,
            availability=CaseAvailabilityFacts(),
            coverage=coverage,
            gaps=(),
            finding_states=(),
            applicable_check=ahead,
        )


def test_receipt_version_slice_is_exact() -> None:
    context = _context(check=_check(CheckVerdict.NO_ISSUE_DETECTED, _coverage()))
    receipt = _build(context)
    assert receipt.versions is not None
    assert receipt.versions.resource_manifest_digest == "sha256:" + "9" * 64
    with pytest.raises(ValueError, match="receipt_build_context_invalid"):
        build_receipt(
            context,
            receipt.receipt_id,
            receipt.task_id,
            receipt.session_id,
            receipt.generated_at,
            cast(ReceiptVersionSlice, {"engine_version": "0.1.0"}),
            ReceiptRedactionProfile.FULL_LOCAL,
            ReceiptInclude.FULL,
        )


def test_builder_never_adds_new_findings_or_evidence() -> None:
    finding = _finding()
    check = _check(CheckVerdict.ACTION_REQUIRED, _coverage(), returned=(finding.finding_id,))
    receipt = _build(_context(finding=finding, check=check))
    assert receipt.findings == (finding,)
    assert receipt.evidence_refs == ()


def test_semantic_review_not_configured_limitations_state_not_run() -> None:
    """Requirement: receipt limitations disclose that AI-powered relevance review was not run."""

    from finishup.domain.receipts import SEMANTIC_REVIEW_NOT_CONFIGURED_GAP, render_receipt_compact

    gap = CaseGap(
        f"semantic_outcome:{SEMANTIC_REVIEW_NOT_CONFIGURED_GAP}",
        SEMANTIC_REVIEW_NOT_CONFIGURED_GAP,
        (),
    )
    coverage = _coverage(gaps=(SEMANTIC_REVIEW_NOT_CONFIGURED_GAP,))
    check = _check(
        CheckVerdict.INSUFFICIENT_COVERAGE,
        coverage,
    )
    # Override AI-powered outcome on the applicable check for documentation; gaps drive disclosure.
    check = replace(
        check,
        semantic_status=SemanticStatus.NOT_CONFIGURED,
        semantic_reason=SemanticReason.PROVIDER_NOT_CONFIGURED,
    )
    receipt = _build(_context(coverage=coverage, gaps=(gap,), check=check))
    assert receipt.conclusion is ReceiptConclusion.INSUFFICIENT_COVERAGE
    assert SEMANTIC_REVIEW_NOT_CONFIGURED_GAP in {item.code for item in receipt.gaps}
    limitations = next(
        section
        for section in receipt.sections
        if section.key is ReceiptSectionKey.LIMITATIONS_AND_COVERAGE
    )
    assert limitations.body.startswith("AI-powered relevance review was not run.")
    assert SEMANTIC_REVIEW_NOT_CONFIGURED_GAP in limitations.items
    rendered = render_receipt_compact(receipt)
    assert "AI-powered relevance review was not run" in rendered
    assert "optional AI-powered review was blocked" not in rendered
    assert "coordinator_failure" not in rendered


def test_coordinator_failure_limitations_name_the_fault_on_every_rendering() -> None:
    """Issue #1077: a real coordinator failure stays the same gap and names the FinishUP fault."""

    from finishup.application.receipt import (
        _internal_result,  # pyright: ignore[reportPrivateUsage]
    )
    from finishup.cli.render import render_human_receipt
    from finishup.domain.receipts import (
        COORDINATOR_FAILURE_LIMITATION,
        SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP,
        render_receipt_compact,
    )
    from finishup.mcp.summaries import summary_for_receipt
    from finishup.protocol.canonical import canonical_encode
    from finishup.protocol.models import CoverageModel, ReceiptFormat, ReceiptSuccessModel

    gap = CaseGap(
        f"semantic_outcome:{SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP}",
        SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP,
        (),
    )
    coverage = _coverage(gaps=(SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP,))

    def _receipt(reason: SemanticReason, status: SemanticStatus):
        check = replace(
            _check(CheckVerdict.INSUFFICIENT_COVERAGE, coverage),
            semantic_status=status,
            semantic_reason=reason,
        )
        return _build(_context(coverage=coverage, gaps=(gap,), check=check))

    receipt = _receipt(SemanticReason.COORDINATOR_FAILURE, SemanticStatus.FAILED)
    assert SEMANTIC_RELEVANCE_REVIEW_NOT_RUN_GAP in {item.code for item in receipt.gaps}
    limitations = next(
        section
        for section in receipt.sections
        if section.key is ReceiptSectionKey.LIMITATIONS_AND_COVERAGE
    )
    assert limitations.body.startswith(COORDINATOR_FAILURE_LIMITATION)
    assert "AI-powered relevance review was not run." not in limitations.body
    for markdown in (True, False):
        rendered = render_receipt_human(receipt, markdown=markdown)
        assert rendered.count(COORDINATOR_FAILURE_LIMITATION) == 1
    compact = render_receipt_compact(receipt)
    assert "AI-powered review failed inside FinishUP (coordinator_failure)" in compact
    assert "AI-powered relevance review was not run" not in compact

    for output_format in (ReceiptFormat.JSON, ReceiptFormat.MARKDOWN, ReceiptFormat.TEXT):
        request = SimpleNamespace(
            format=output_format,
            request_id="req_00000000-0000-4000-8000-000000000001",
            redaction_profile=ReceiptRedactionProfile.FULL_LOCAL,
            include=ReceiptInclude.FULL,
            writer_id=None,
        )
        result = _internal_result(
            cast(Any, request),
            receipt,
            cast(Any, SimpleNamespace(object_id="obj_00000000-0000-4000-8000-000000000001")),
            "sha256:" + "3" * 64,
            _FRONTIER,
        )
        envelope = result.as_json()
        summary = summary_for_receipt(envelope)
        fields: dict[str, Any] = {
            **envelope,
            "coverage": CoverageModel.model_validate(envelope["coverage"]),
        }
        cli = render_human_receipt(ReceiptSuccessModel.model_construct(**fields))
        if output_format is ReceiptFormat.JSON:
            assert COORDINATOR_FAILURE_LIMITATION in summary
            assert COORDINATOR_FAILURE_LIMITATION in cli
            assert cli.count(COORDINATOR_FAILURE_LIMITATION) == 1
            encoded = canonical_encode(result.document).decode("utf-8")
            assert COORDINATOR_FAILURE_LIMITATION in encoded
        else:
            assert result.human_text is not None
            assert result.human_text.count(COORDINATOR_FAILURE_LIMITATION) == 1
            assert COORDINATOR_FAILURE_LIMITATION in cli
            assert cli.count(COORDINATOR_FAILURE_LIMITATION) == 1

    timeout = replace(
        _check(
            CheckVerdict.INSUFFICIENT_COVERAGE,
            coverage,
            semantic_provenance=replace(
                _provenance(),
                status=SemanticStatus.TIMEOUT,
                reason=SemanticReason.PROVIDER_TIMEOUT,
            ),
        ),
    )
    other = _build(_context(coverage=coverage, gaps=(gap,), check=timeout))
    other_limitations = next(
        section
        for section in other.sections
        if section.key is ReceiptSectionKey.LIMITATIONS_AND_COVERAGE
    )
    assert other_limitations.body.startswith("AI-powered relevance review was not run.")
    assert COORDINATOR_FAILURE_LIMITATION not in other_limitations.body
    assert "AI-powered relevance review was not run" in render_receipt_compact(other)
    assert "coordinator_failure" not in render_receipt_compact(other)


def test_scoped_deterministic_clean_keeps_the_review_gap_in_the_receipt() -> None:
    """A scoped check result never upgrades the receipt past its standing coverage limit."""

    from finishup.domain.receipts import SEMANTIC_REVIEW_NOT_REQUESTED_GAP

    coverage = _coverage(gaps=(SEMANTIC_REVIEW_NOT_REQUESTED_GAP,))
    gap = CaseGap(
        f"semantic_outcome:{SEMANTIC_REVIEW_NOT_REQUESTED_GAP}",
        SEMANTIC_REVIEW_NOT_REQUESTED_GAP,
        (),
    )
    check = _check(CheckVerdict.NO_ISSUE_DETECTED, coverage)
    receipt = _build(_context(coverage=coverage, gaps=(gap,), check=check))

    assert receipt.conclusion is ReceiptConclusion.INSUFFICIENT_COVERAGE
    assert SEMANTIC_REVIEW_NOT_REQUESTED_GAP in {item.code for item in receipt.gaps}
    for markdown in (True, False):
        rendered = render_receipt_human(receipt, markdown=markdown)
        assert "AI-powered review was not requested (local-only check)." in rendered
        assert SEMANTIC_REVIEW_NOT_REQUESTED_GAP in rendered


@pytest.mark.parametrize("profile", tuple(ReceiptRedactionProfile))
@pytest.mark.parametrize("reason", tuple(NoObligationsReason))
def test_empty_completion_scope_wording_is_bounded_and_survives_profiles(
    profile: ReceiptRedactionProfile,
    reason: NoObligationsReason,
) -> None:
    plan = PlanPublishedPayload(1, "Atomic task", (), ())
    undeclared_gap = CaseGap(
        "completion_scope_undeclared:plan",
        COMPLETION_SCOPE_UNDECLARED_GAP,
        (),
    )
    undeclared_coverage = _coverage(gaps=(COMPLETION_SCOPE_UNDECLARED_GAP,))
    undeclared = _build(
        _context(
            check=_check(CheckVerdict.INSUFFICIENT_COVERAGE, undeclared_coverage),
            coverage=undeclared_coverage,
            gaps=(undeclared_gap,),
            plan=plan,
        ),
        profile=profile,
    )
    assert undeclared.conclusion is ReceiptConclusion.INSUFFICIENT_COVERAGE
    outstanding = next(
        section
        for section in undeclared.sections
        if section.key is ReceiptSectionKey.OUTSTANDING_WORK
    )
    assert outstanding.body == "Completion scope was never declared."
    assert "completion scope was never declared" in render_receipt_compact(undeclared)

    typed_plan = replace(
        plan,
        no_obligations_reason=reason,
    )
    declared_gap = CaseGap(
        "completion_scope_declared_none:plan",
        COMPLETION_SCOPE_DECLARED_NONE_GAP,
        (),
    )
    declared_coverage = _coverage(gaps=(COMPLETION_SCOPE_DECLARED_NONE_GAP,))
    declared = _build(
        _context(
            check=_check(CheckVerdict.INSUFFICIENT_COVERAGE, declared_coverage),
            coverage=declared_coverage,
            gaps=(declared_gap,),
            plan=typed_plan,
        ),
        profile=profile,
    )
    assert declared.conclusion is ReceiptConclusion.INSUFFICIENT_COVERAGE
    outstanding = next(
        section
        for section in declared.sections
        if section.key is ReceiptSectionKey.OUTSTANDING_WORK
    )
    assert outstanding.body == f"The plan declared none, reason: {reason.value}."
    assert declared.gaps[0].detail == reason.value
    assert f"the plan declared none, reason: {reason.value}" in render_receipt_compact(declared)
    assert "Atomic task" not in render_receipt_compact(declared)


@pytest.mark.parametrize(
    "gap_code",
    (COMPLETION_SCOPE_UNDECLARED_GAP, COMPLETION_SCOPE_DECLARED_NONE_GAP),
)
def test_empty_completion_scope_gap_dominates_unresolved_actionable_finding(
    gap_code: str,
) -> None:
    finding = _finding()
    gap = CaseGap(f"{gap_code}:plan", gap_code, ())
    coverage = _coverage(gaps=(gap_code,))
    reason = (
        NoObligationsReason.SINGLE_ATOMIC_CHANGE
        if gap_code == COMPLETION_SCOPE_DECLARED_NONE_GAP
        else None
    )
    plan = PlanPublishedPayload(1, "Atomic task", (), (), reason)
    receipt = _build(
        _context(
            finding=finding,
            check=_check(
                CheckVerdict.INSUFFICIENT_COVERAGE,
                coverage,
                returned=(finding.finding_id,),
            ),
            coverage=coverage,
            gaps=(gap,),
            plan=plan,
        )
    )

    assert receipt.findings == (finding,)
    assert receipt.conclusion is ReceiptConclusion.INSUFFICIENT_COVERAGE


def test_frozen_scope_gap_without_current_relation_omits_zero_detail() -> None:
    """A repaired current projection must not render a stale frozen gap as zero relations."""

    coverage = _coverage(gaps=(COMPLETION_CLAIM_OUTSIDE_PLAN_GAP,))
    gap = CaseGap(
        f"check_coverage:{COMPLETION_CLAIM_OUTSIDE_PLAN_GAP}",
        COMPLETION_CLAIM_OUTSIDE_PLAN_GAP,
        (),
    )
    receipt = _build(
        _context(
            check=_check(CheckVerdict.INSUFFICIENT_COVERAGE, coverage),
            coverage=coverage,
            gaps=(gap,),
        )
    )

    rendered_gap = next(
        item for item in receipt.gaps if item.code == COMPLETION_CLAIM_OUTSIDE_PLAN_GAP
    )
    assert rendered_gap.detail is None


def test_declared_resolved_scope_has_distinct_clean_wording() -> None:
    obligation = ObligationPublishedPayload(
        obligation_id("obl_00000000-0000-4000-8000-000000000020"),
        "Run focused verification",
        "Recorded successful result",
        ObligationStatus.RESOLVED,
        resolution_evidence_refs=(result_id("res_00000000-0000-4000-8000-000000000020"),),
    )
    plan = PlanPublishedPayload(1, "Verified task", (obligation.obligation_id,), ())
    receipt = _build(
        _context(
            check=_check(CheckVerdict.NO_ISSUE_DETECTED, _coverage()),
            plan=plan,
            obligation=obligation,
        )
    )
    outstanding = next(
        section for section in receipt.sections if section.key is ReceiptSectionKey.OUTSTANDING_WORK
    )
    assert receipt.conclusion is ReceiptConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS
    assert outstanding.body == "Declared obligations are all resolved."
    assert "declared obligations are all resolved" in render_receipt_compact(receipt)


def test_compact_resolved_wording_ignores_out_of_scope_open_finding_obligation() -> None:
    effective = ObligationPublishedPayload(
        obligation_id("obl_00000000-0000-4000-8000-000000000020"),
        "Run focused verification",
        "Recorded successful result",
        ObligationStatus.RESOLVED,
        resolution_evidence_refs=(result_id("res_00000000-0000-4000-8000-000000000020"),),
    )
    historical = ObligationPublishedPayload(
        obligation_id("obl_00000000-0000-4000-8000-000000000001"),
        "Historical finding subject",
        "Historical acceptance criterion",
        ObligationStatus.OPEN,
    )
    finding = _finding()
    plan = PlanPublishedPayload(1, "Verified task", (effective.obligation_id,), ())
    base = _context(
        finding=finding,
        resolved=True,
        check=_check(CheckVerdict.NO_ISSUE_DETECTED, _coverage()),
        plan=plan,
        obligation=effective,
    )
    projection = replace(
        base.projection,
        obligations={
            **base.projection.obligations,
            historical.obligation_id: ObligationProjectionRecord(
                payload=historical,
                payload_digest=canonical_digest(encode_payload(historical)),
                redacted=False,
                source_event_id=event_id("evt_00000000-0000-4000-8000-000000000012"),
                source_frontier=1,
            ),
        },
    )
    context = replace(base, projection=projection)

    receipt = _build(context)

    assert tuple(item.status for item in receipt.obligations) == (
        ReceiptObligationStatus.OPEN,
        ReceiptObligationStatus.RESOLVED,
    )
    outstanding = next(
        section for section in receipt.sections if section.key is ReceiptSectionKey.OUTSTANDING_WORK
    )
    assert outstanding.body == "Declared obligations are all resolved."
    assert "declared obligations are all resolved" in render_receipt_compact(receipt)


@pytest.mark.parametrize("state", ("missing", "redacted", "unreadable_plan"))
def test_unknown_effective_obligation_scope_never_renders_as_zero(state: str) -> None:
    obligation = ObligationPublishedPayload(
        obligation_id("obl_00000000-0000-4000-8000-000000000030"),
        "Inspect declared work",
        "Recorded result",
        ObligationStatus.OPEN,
    )
    plan = PlanPublishedPayload(1, "Declared scope", (obligation.obligation_id,), ())
    gap_code = "missing_ref" if state == "missing" else "redacted_event"
    gap = CaseGap(f"{gap_code}:scope", gap_code, ())
    coverage = _coverage(gaps=(gap_code,))
    receipt = _build(
        _context(
            check=_check(CheckVerdict.INSUFFICIENT_COVERAGE, coverage),
            coverage=coverage,
            gaps=(gap,),
            plan=plan,
            obligation=None if state == "missing" else obligation,
            plan_redacted=state == "unreadable_plan",
            obligation_redacted=state == "redacted",
        )
    )
    outstanding = next(
        section for section in receipt.sections if section.key is ReceiptSectionKey.OUTSTANDING_WORK
    )
    assert receipt.conclusion is ReceiptConclusion.INSUFFICIENT_COVERAGE
    assert "unknown" in outstanding.body
    assert "No open obligations are recorded" not in outstanding.body
    assert "all resolved" not in outstanding.body


def test_no_plan_receipt_does_not_infer_zero_obligations() -> None:
    receipt = _build(_context(check=_check(CheckVerdict.NO_ISSUE_DETECTED, _coverage())))
    outstanding = next(
        section for section in receipt.sections if section.key is ReceiptSectionKey.OUTSTANDING_WORK
    )
    assert outstanding.body == "No plan is recorded; completion scope is unknown."


def test_compact_renderer_never_echoes_unrecognized_scope_reason_detail() -> None:
    plan = PlanPublishedPayload(
        1,
        "Caller-controlled plan prose must not render",
        (),
        (),
        NoObligationsReason.NO_MATERIAL_CHANGE,
    )
    gap = CaseGap("completion_scope_declared_none:plan", COMPLETION_SCOPE_DECLARED_NONE_GAP, ())
    coverage = _coverage(gaps=(COMPLETION_SCOPE_DECLARED_NONE_GAP,))
    receipt = _build(
        _context(
            check=_check(CheckVerdict.INSUFFICIENT_COVERAGE, coverage),
            coverage=coverage,
            gaps=(gap,),
            plan=plan,
        )
    )
    tampered = replace(receipt, gaps=(replace(receipt.gaps[0], detail="CALLER SECRET"),))
    rendered = render_receipt_compact(tampered)
    assert "CALLER SECRET" not in rendered
    assert "closed reason is unavailable" in rendered


def test_resolved_history_is_named_apart_from_current_findings_and_gaps() -> None:
    """A resolved finding stays in the document as history, is listed by id in the summary
    section (the one every include level carries), and the fixed templates say so beside the
    current count so a reader can tell "was fixed" from "still open" and from coverage limits."""

    finding = _finding()
    receipt = _build(
        _context(
            finding=finding,
            resolved=True,
            check=_check(CheckVerdict.NO_ISSUE_DETECTED, _coverage()),
        ),
        include=ReceiptInclude.STANDARD,
    )
    assert receipt.conclusion is ReceiptConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS
    assert receipt.findings == (finding,)
    sections = {section.key: section for section in receipt.sections}
    summary = sections[ReceiptSectionKey.SUMMARY]
    assert summary.items == (finding.finding_id,)
    assert summary.body == (
        "No unresolved local findings were recorded at frontier 2. One earlier finding "
        "was resolved by a later qualifying check and remains visible as history."
    )
    dispositions = sections[ReceiptSectionKey.FINDINGS_AND_DISPOSITIONS]
    assert dispositions.items == ()
    assert dispositions.body == (
        "No findings remain open. One earlier finding was resolved by a later qualifying check "
        "and remains visible as history."
    )
    assert resolved_finding_ids_for_render(receipt) == frozenset({finding.finding_id})
    assert unresolved_findings_for_render(receipt) == ()
    compact = render_receipt_compact(receipt)
    assert "no unresolved local findings were recorded" in compact
    assert "1 unresolved finding" not in compact


def test_resolved_history_beside_a_current_finding_counts_only_the_current_one() -> None:
    current = _finding()
    resolved = replace(
        current,
        finding_id=finding_id("fnd_00000000-0000-4000-8000-000000000002"),
        subject_refs=(obligation_id("obl_00000000-0000-4000-8000-000000000002"),),
    )
    base = _context(
        finding=current,
        check=_check(CheckVerdict.ACTION_REQUIRED, _coverage(), returned=(current.finding_id,)),
    )
    projection = replace(
        base.projection,
        findings={
            **base.projection.findings,
            resolved.finding_id: FindingProjectionRecord(
                payload=resolved,
                payload_digest=canonical_digest(encode_payload(resolved)),
                redacted=False,
                source_event_id=event_id("evt_00000000-0000-4000-8000-000000000013"),
                source_frontier=1,
                resolved_by_check_event_id=_CHECK_EVENT_ID,
            ),
        },
    )
    context = replace(
        base,
        projection=projection,
        finding_states=(
            ReceiptFindingState(current.finding_id, resolved=False),
            ReceiptFindingState(resolved.finding_id, resolved=True),
        ),
    )
    receipt = _build(context, include=ReceiptInclude.SUMMARY)
    assert receipt.conclusion is ReceiptConclusion.UNRESOLVED_FINDINGS_REMAIN
    assert len(receipt.findings) == 2
    summary = next(s for s in receipt.sections if s.key is ReceiptSectionKey.SUMMARY)
    assert summary.items == (resolved.finding_id,)
    assert summary.body.startswith("One actionable finding remain unresolved at frontier 2.")
    assert "One earlier finding was resolved by a later qualifying check" in summary.body
    assert unresolved_findings_for_render(receipt) == (current,)
    assert render_receipt_compact(receipt).endswith("1 unresolved finding remains.")


def _provenance() -> SemanticProvenance:
    return SemanticProvenance(
        provider="fake",
        endpoint_profile_id="fake",
        endpoint_profile_version="1.0.0",
        model="fake/model",
        sdk_version="1.0.0",
        prompt_digest=_DIGEST,
        schema_digest=_DIGEST,
        policy_digest=_DIGEST,
        privacy_policy_digest=_DIGEST,
        sampling_params=SamplingParams(128),
        latency_ms=1,
        semantic_attempt_id="att_00000000-0000-4000-8000-000000000001",
        dispatch_kind=SemanticDispatchKind.EXTERNAL,
        privacy_receipt_id="egr_00000000-0000-4000-8000-000000000001",
        status=SemanticStatus.SUCCEEDED,
        reason=SemanticReason.SEMANTIC_COMPLETED,
        provider_request_id="fake-1",
        egress_authorization_id="aut_00000000-0000-4000-8000-000000000001",
        request_commitment="hmac-sha256:" + "b" * 64,
    )


def _review_input_manifest(*, specification_status: str = "title_only") -> dict[str, object]:
    digest = "sha256:" + "c" * 64

    def section(status: str, content_digest: str | None = digest) -> dict[str, object]:
        return {
            "status": status,
            "source_refs": ["evt_00000000-0000-4000-8000-000000000001"],
            "item_ids": ["item-1"],
            "omitted_refs": [],
            "omission_reasons": [],
            "revision": 6,
            "content_digest": content_digest,
            "content_bytes": 88,
        }

    return {
        "schema": "yoetz.review-input-manifest/1",
        "specification": section(specification_status),
        "current_diff": section("complete"),
        "caller_evidence": section("partial"),
        "latest_verification": section("missing", None),
        "prior_finding_context": section("not_selected", None),
        "phase": "provider_bound",
        "missing_inputs": [],
        "selected_item_count": 2,
        "selected_excerpt_bytes": 176,
        "omitted_item_count": 1,
    }


def test_receipt_projects_provider_bound_input_metadata_in_all_formats() -> None:
    code = "semantic_packet_insufficient"
    coverage = _coverage(gaps=(code,))
    missing = MissingForAssessmentItem(
        kind="verification_output",
        target_refs=("res_00000000-0000-4000-8000-000000000002",),
        availability="agent_suppliable",
    )
    check = _check(
        CheckVerdict.INSUFFICIENT_COVERAGE,
        coverage,
        semantic_provenance=_provenance(),
        semantic_conclusion="insufficient_packet",
        missing_for_assessment=(missing,),
        review_input_manifest=_review_input_manifest(),
    )

    receipt = _build(
        _context(
            coverage=coverage,
            gaps=(CaseGap(code, code, ()),),
            check=check,
        )
    )
    limitations = next(
        section
        for section in receipt.sections
        if section.key is ReceiptSectionKey.LIMITATIONS_AND_COVERAGE
    )
    assert limitations.coverage_note is not None
    assert "phase" not in limitations.coverage_note
    assert "provider_bound" in limitations.coverage_note
    assert "specification: title_only" in limitations.coverage_note
    assert "verification_output (1 target refs): agent_suppliable" in limitations.coverage_note

    wire = receipt_document_to_json(receipt)
    wire_sections = cast(list[dict[str, object]], wire["sections"])
    json_limitations = next(
        section for section in wire_sections if section["key"] == "limitations_and_coverage"
    )
    assert json_limitations["coverage_note"] == limitations.coverage_note
    markdown = render_receipt_human(receipt, markdown=True)
    text = render_receipt_human(receipt, markdown=False)
    for rendered in (markdown, text):
        assert "Review input coverage (metadata only):" in rendered
        assert "provider_bound" in rendered
        assert "specification: title_only" in rendered
        assert "agent_suppliable" in rendered


def _subscription_provenance() -> SemanticProvenance:
    usage = RuntimeTokenUsage(
        input_tokens=100,
        cached_input_tokens=60,
        cache_write_input_tokens=5,
        output_tokens=20,
        reasoning_output_tokens=8,
        total_tokens=120,
    )
    runtime = RuntimeAttemptEvidence(
        credential_authority="external_runtime_oauth",
        runtime_version="0.150.1",
        runtime_source_identity="openai-codex-npm-darwin-arm64-0.150.1",
        executable_sha256=_DIGEST,
        app_server_schema_sha256=_DIGEST,
        capability_cell_sha256=_DIGEST,
        capability_profile="codex-evaluator/0.150.1/v1",
        capability_evidence_expires_at="2026-11-30T00:00:00Z",
        launcher_sha256=_DIGEST,
        isolated_config_sha256=_DIGEST,
        disclosed_case_sha256=_DIGEST,
        instruction_sha256=_DIGEST,
        output_schema_sha256=_DIGEST,
        selection_sha256=_DIGEST,
        upstream_body_observability="unavailable",
        auth_mode="chatgpt",
        plan_type="plus",
        reasoning_effort="high",
        thread_id="thread-1",
        turn_id="turn-1",
        final_output_sha256=_DIGEST,
        case_disclosed=True,
        turn_acknowledged=True,
        process_cleanup="terminated",
        token_usage=usage,
    )
    return replace(
        _provenance(),
        dispatch_kind=SemanticDispatchKind.EXTERNAL_RUNTIME_OAUTH,
        token_usage=usage.aggregate,
        runtime_evidence=runtime,
    )


def test_receipt_carries_applicable_semantic_provenance_and_usage() -> None:
    provenance = _subscription_provenance()
    receipt = _build(
        _context(
            check=_check(
                CheckVerdict.NO_ISSUE_DETECTED,
                _coverage(),
                semantic_provenance=provenance,
            )
        )
    )

    assert receipt.semantic_provenance == provenance
    wire = receipt_document_to_json(receipt)
    assert wire["semantic_provenance"] == semantic_provenance_to_json(provenance)
    assert receipt_document_from_json(wire) == receipt
    version_section = next(
        section
        for section in receipt.sections
        if section.key is ReceiptSectionKey.VERSION_AND_POLICY_IDENTITY
    )
    assert (
        "AI-powered review attempt usage: input=100, cached_input=60, cache_write_input=5, "
        "output=20, reasoning_output=8, total=120 tokens."
    ) in version_section.body
    # Issue #571: the exact per-check selection is named beside the usage it produced.
    assert (
        f"AI-powered review selection: model={provenance.model}, reasoning_effort=high, "
        f"output_limit={provenance.sampling_params.max_output_tokens} tokens."
    ) in version_section.body
    rendered = render_receipt_human(receipt, markdown=False)
    assert "input=100" in rendered
    assert "thread-1" not in rendered
    assert "provider_request_id" not in rendered


def test_receipt_carries_opaque_withheld_item_identity_and_reason() -> None:
    receipt = _build(
        _context(
            coverage=_coverage(gaps=("content_redacted",)),
            gaps=(CaseGap("content_redacted", "content_redacted", ()),),
            check=_check(
                CheckVerdict.NO_ISSUE_DETECTED,
                _coverage(gaps=("content_redacted",)),
                semantic_withheld_item_ids=("excerpt-heuristic",),
            ),
        )
    )

    assert tuple(item.item_id for item in receipt.semantic_withheld_items) == ("excerpt-heuristic",)
    assert receipt.semantic_withheld_items[0].reason == "never_send_heuristic"
    rendered = render_receipt_human(receipt, markdown=False)
    assert "excerpt-heuristic" in rendered
    assert "never_send_heuristic" in rendered


_REDACTED = (
    SemanticRedactedValue(
        "excerpt-a", "value_replaced", (3, 7), "evd_10000000-0000-4000-8000-000000000021"
    ),
    SemanticRedactedValue("excerpt-heuristic", "item_withheld", (2,)),
)


def test_check_event_round_trips_redacted_values_and_old_events_decode() -> None:
    """PL2-1 (issue #982): optional 1.4.0 field; events without it decode unchanged."""

    from finishup.domain.events import (
        REVIEW_CHECK_EVENT_SCHEMA_VERSION,
        EventSchema,
        decode_payload,
        encode_payload,
    )

    gaps = ("semantic_review_item_withheld", "semantic_review_value_redacted")
    check = _check(
        CheckVerdict.NO_ISSUE_DETECTED,
        _coverage(gaps=gaps),
        semantic_withheld_item_ids=("excerpt-heuristic",),
        totals=_totals(),
        semantic_redacted_values=_REDACTED,
    )
    schema = EventSchema("check_recorded", REVIEW_CHECK_EVENT_SCHEMA_VERSION)
    wire = encode_payload(check)
    assert isinstance(wire, Mapping)
    entries = cast(tuple[Mapping[str, object], ...], wire["semantic_redacted_values"])
    assert entries[0]["lines"] == (3, 7)
    assert "abcdefgh" not in repr(wire)
    assert decode_payload(schema, wire) == check
    old = _check(
        CheckVerdict.NO_ISSUE_DETECTED,
        _coverage(gaps=gaps),
        semantic_withheld_item_ids=("excerpt-heuristic",),
        totals=_totals(),
    )
    old_wire = encode_payload(old)
    assert isinstance(old_wire, Mapping)
    assert "semantic_redacted_values" not in old_wire
    decoded_old = decode_payload(schema, old_wire)
    assert isinstance(decoded_old, CheckRecordedPayload)
    assert decoded_old.semantic_redacted_values == ()
    with pytest.raises(ValueError):
        # An item_withheld entry must name a withheld item.
        _check(
            CheckVerdict.NO_ISSUE_DETECTED,
            _coverage(gaps=gaps),
            totals=_totals(),
            semantic_redacted_values=_REDACTED,
        )


def test_receipt_carries_redacted_value_lines_and_the_fixed_agent_line() -> None:
    gaps = ("semantic_review_item_withheld", "semantic_review_value_redacted")
    receipt = _build(
        _context(
            coverage=_coverage(gaps=gaps),
            gaps=tuple(CaseGap(code, code, ()) for code in gaps),
            check=_check(
                CheckVerdict.NO_ISSUE_DETECTED,
                _coverage(gaps=gaps),
                semantic_withheld_item_ids=("excerpt-heuristic",),
                semantic_redacted_values=_REDACTED,
            ),
        )
    )
    assert receipt.semantic_redacted_values == _REDACTED
    for markdown in (True, False):
        rendered = render_receipt_human(receipt, markdown=markdown)
        assert rendered.count(SEMANTIC_REDACTED_VALUES_AGENT_LINE) == 1
        assert "value replaced, lines 3, 7" in rendered


def test_receipt_omits_absent_semantic_provenance_for_historical_bytes() -> None:
    receipt = _build(_context(check=_check(CheckVerdict.NO_ISSUE_DETECTED, _coverage())))
    wire = receipt_document_to_json(receipt)
    assert "semantic_provenance" not in wire
    assert receipt_document_from_json(wire).semantic_provenance is None


@pytest.mark.parametrize(
    "profile",
    tuple(ReceiptRedactionProfile),
)
def test_receipt_profiles_retain_bounded_semantic_attempt_usage(
    profile: ReceiptRedactionProfile,
) -> None:
    provenance = _subscription_provenance()
    receipt = _build(
        _context(
            check=_check(
                CheckVerdict.NO_ISSUE_DETECTED,
                _coverage(),
                semantic_provenance=provenance,
            )
        ),
        profile=profile,
    )
    assert receipt.semantic_provenance == provenance
    assert receipt_document_to_json(receipt)["semantic_provenance"] == (
        semantic_provenance_to_json(provenance)
    )
    assert "total=120 tokens" in render_receipt_human(receipt, markdown=False)


def test_redacted_share_does_not_leak_omitted_resolved_finding_ids() -> None:
    """A profile that omits a finding row must not name its id as resolved history either."""

    semantic = replace(
        _finding(),
        finding_id=finding_id("fnd_00000000-0000-4000-8000-000000000003"),
        origin=FindingOrigin.SEMANTIC_MODEL_DERIVED,
        provenance=_provenance(),
    )
    receipt = _build(
        _context(
            finding=semantic,
            resolved=True,
            check=_check(CheckVerdict.NO_ISSUE_DETECTED, _coverage()),
        ),
        profile=ReceiptRedactionProfile.REDACTED_SHARE,
        include=ReceiptInclude.STANDARD,
    )
    assert receipt.findings == ()
    summary = next(s for s in receipt.sections if s.key is ReceiptSectionKey.SUMMARY)
    assert summary.items == ()
    assert "resolved by a later qualifying check" not in summary.body
    assert resolved_finding_ids_for_render(receipt) == frozenset()


def test_registration_drift_gap_names_policy_recovery_in_limitations() -> None:
    """Issue #537 slice C: applied-policy-serving-strict names the recovery in Limitations."""

    from finishup.domain.receipts import (
        OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP,
        OPTIONAL_SEMANTIC_REVIEW_REGISTRATION_DRIFT_GAP,
    )

    gaps = (
        OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP,
        OPTIONAL_SEMANTIC_REVIEW_REGISTRATION_DRIFT_GAP,
    )
    coverage = _coverage(gaps=gaps)
    case_gaps = tuple(CaseGap(code, code, ()) for code in gaps)
    receipt = _build(
        _context(
            coverage=coverage,
            gaps=case_gaps,
            check=_check(CheckVerdict.NO_ISSUE_DETECTED, coverage),
        )
    )
    section = next(
        item for item in receipt.sections if item.key is ReceiptSectionKey.LIMITATIONS_AND_COVERAGE
    )
    assert "the last install applied the policy route" in section.body
    # A strict route reached outside the ceremony is a legitimate owner action, so the
    # section reports the disagreement and offers the recovery conditionally.
    assert "If this strict route was not intended" in section.body
    assert "is stale" not in section.body
    assert "finishup integrate codex mcp install --route-profile policy" in section.body
    assert "start a fresh Codex process" in section.body
    assert section.items == gaps


def test_genuine_strict_ceiling_keeps_generic_limitations_wording() -> None:
    """A genuinely applied strict route keeps today's terminal Limitations wording exactly."""

    from finishup.domain.receipts import OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP

    coverage = _coverage(gaps=(OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP,))
    receipt = _build(
        _context(
            coverage=coverage,
            gaps=(
                CaseGap(
                    OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP,
                    OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP,
                    (),
                ),
            ),
            check=_check(CheckVerdict.NO_ISSUE_DETECTED, coverage),
        )
    )
    section = next(
        item for item in receipt.sections if item.key is ReceiptSectionKey.LIMITATIONS_AND_COVERAGE
    )
    assert section.body == (
        f"Coverage is limited by: {OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP}."
    )
    assert section.items == (OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP,)


def test_selection_summary_and_input_loss_remain_distinct_in_all_receipt_formats() -> None:
    gaps = ("observation_input_loss", "routine_read_detail_omitted")
    coverage = _coverage(gaps=gaps)
    receipt = _build(
        _context(
            coverage=coverage,
            gaps=tuple(CaseGap(code, code, ()) for code in gaps),
            check=_check(CheckVerdict.NO_ISSUE_DETECTED, coverage),
        )
    )
    assert receipt.conclusion is ReceiptConclusion.INSUFFICIENT_COVERAGE
    serialized = str(receipt_document_to_json(receipt))
    for rendered in (
        serialized,
        render_receipt_human(receipt, markdown=True),
        render_receipt_human(receipt, markdown=False),
    ):
        assert "bounded source summaries" in rendered
        assert "historical loss remains a limitation after queue recovery" in rendered
        assert "new time and state only" in rendered


@pytest.mark.parametrize(
    ("gaps", "sentences"),
    [
        (
            ("task_statement_not_authorized", "task_statement_unavailable"),
            (
                "did not receive the task statement",
                "does not list the task_statement review section",
            ),
        ),
        (("task_statement_not_supplied",), ("start.task_statement",)),
    ],
)
def test_task_statement_limitation_is_disclosed_in_every_receipt_format(
    gaps: tuple[str, ...], sentences: tuple[str, ...]
) -> None:
    """Criterion 1 (issue #908): JSON, markdown and text receipts all say it in words."""

    coverage = _coverage(gaps=gaps)
    receipt = _build(
        _context(
            coverage=coverage,
            gaps=tuple(CaseGap(code, code, ()) for code in gaps),
            check=_check(CheckVerdict.NO_ISSUE_DETECTED, coverage),
        )
    )
    assert receipt.conclusion is ReceiptConclusion.INSUFFICIENT_COVERAGE
    assert {gap.code for gap in receipt.gaps} >= set(gaps)
    assert all(gap.detail for gap in receipt.gaps if gap.code in gaps)
    serialized = str(receipt_document_to_json(receipt))
    for rendered in (
        serialized,
        render_receipt_human(receipt, markdown=True),
        render_receipt_human(receipt, markdown=False),
    ):
        for code in gaps:
            assert code in rendered
        for sentence in sentences:
            assert sentence in rendered


def _renderings(receipt: ReceiptDocument) -> tuple[str, str, str]:
    return (
        str(receipt_document_to_json(receipt)),
        render_receipt_human(receipt, markdown=True),
        render_receipt_human(receipt, markdown=False),
    )


_TITLE_ONLY_SENTENCE = "had at most the task title in place of the user's request"
_TRANSCRIBED_SENTENCE = "the agent's transcription of the user's request"


@pytest.mark.parametrize(
    ("statement", "sentence", "source"),
    [
        (None, _TITLE_ONLY_SENTENCE, "task_title_only"),
        (
            "Under Ascii, Style.Truncate returns plain text without tail.",
            _TRANSCRIBED_SENTENCE,
            "agent_transcribed",
        ),
    ],
)
def test_task_statement_source_is_disclosed_in_every_receipt_format(
    statement: str | None, sentence: str, source: str
) -> None:
    """Review 942-G4 (issue #908): a title-only review must not read like one with the request."""

    from builders.replay import genesis_session_opened_variant

    opened = genesis_session_opened_variant(version="1.2.0", statement=statement)
    check = _check(CheckVerdict.NO_ISSUE_DETECTED, _coverage(), semantic_provenance=_provenance())
    receipt = _build(replace(_context(check=check), records=(opened,)))
    for rendered in _renderings(receipt):
        assert sentence in rendered
        assert source in rendered
    other = _TRANSCRIBED_SENTENCE if sentence == _TITLE_ONLY_SENTENCE else _TITLE_ONLY_SENTENCE
    assert all(other not in rendered for rendered in _renderings(receipt))


def test_task_statement_source_is_not_claimed_without_a_completed_review_or_history() -> None:
    from builders.replay import genesis_session_opened_variant

    opened = genesis_session_opened_variant(version="1.2.0", statement=None)
    deterministic = _check(CheckVerdict.NO_ISSUE_DETECTED, _coverage())
    reviewed = _check(
        CheckVerdict.NO_ISSUE_DETECTED, _coverage(), semantic_provenance=_provenance()
    )
    for receipt in (
        # No AI-powered review ran, so there is nothing to say about what it saw.
        _build(replace(_context(check=deterministic), records=(opened,))),
        # Without the ledger history the receipt cannot know, so it says nothing.
        _build(_context(check=reviewed)),
    ):
        for rendered in _renderings(receipt):
            assert _TITLE_ONLY_SENTENCE not in rendered
            assert _TRANSCRIBED_SENTENCE not in rendered


def test_a_redacted_statement_event_is_not_reported_as_title_only() -> None:
    from builders.replay import genesis_session_opened_variant
    from finishup.domain.events import RedactionState

    opened = genesis_session_opened_variant(
        version="1.2.0", statement="The request.", redaction=RedactionState.LOGICALLY_REDACTED
    )
    check = _check(CheckVerdict.NO_ISSUE_DETECTED, _coverage(), semantic_provenance=_provenance())
    receipt = _build(replace(_context(check=check), records=(opened,)))
    for rendered in _renderings(receipt):
        assert _TITLE_ONLY_SENTENCE not in rendered


def test_a_withheld_statement_keeps_its_gap_prose_instead_of_a_source_sentence() -> None:
    from builders.replay import genesis_session_opened_variant

    gaps = ("task_statement_not_authorized", "task_statement_unavailable")
    coverage = _coverage(gaps=gaps)
    opened = genesis_session_opened_variant(version="1.2.0", statement="The request.")
    check = _check(CheckVerdict.NO_ISSUE_DETECTED, coverage, semantic_provenance=_provenance())
    context = _context(
        coverage=coverage, gaps=tuple(CaseGap(code, code, ()) for code in gaps), check=check
    )
    receipt = _build(replace(context, records=(opened,)))
    for rendered in _renderings(receipt):
        assert "did not receive the task statement" in rendered
        assert _TRANSCRIBED_SENTENCE not in rendered
        assert _TITLE_ONLY_SENTENCE not in rendered


def test_child_receipt_retains_provider_usage_under_the_combined_contract() -> None:
    from finishup.domain.receipts import ReceiptChildOutcome, ReceiptChildren
    from finishup.protocol.canonical import JsonValue
    from finishup.protocol.schemas import validate_schema_instance

    provenance = _subscription_provenance()
    receipt = _build(
        _context(
            check=_check(
                CheckVerdict.NO_ISSUE_DETECTED, _coverage(), semantic_provenance=provenance
            )
        )
    )
    child = ReceiptChildOutcome(
        child_task_id=task_id("tsk_00000000-0000-4000-8000-000000000099"),
        outcome="unavailable",
        later_manifest_ref=None,
        tested_manifest_ref=None,
        freshness="unknown",
        findings=(),
    )
    receipt = replace(
        receipt,
        versions=replace(
            receipt.versions,
            schema_versions=(SchemaVersionEntry("receipts/receipt-document", "1.3.0"),),
        ),
        children=ReceiptChildren((child,)),
    )
    wire = receipt_document_to_json(receipt)
    validate_schema_instance("receipt-document", "1.3.0", cast(JsonValue, wire))
    restored = receipt_document_from_json(wire)
    assert restored.children.children == (child,)
    assert restored.semantic_provenance == provenance
    assert restored == receipt


@pytest.mark.parametrize("resolved", [False, True])
def test_resolved_semantic_issue_keeps_capture_coverage_limit(resolved: bool) -> None:
    code = "content_unselected"
    coverage = _coverage(gaps=(code,))
    semantic = replace(
        _finding(),
        origin=FindingOrigin.SEMANTIC_MODEL_DERIVED,
        provenance=_provenance(),
        coverage=coverage,
    )
    receipt = _build(
        _context(
            finding=semantic,
            resolved=resolved,
            coverage=coverage,
            gaps=(CaseGap(code, code, ()),),
            check=_check(CheckVerdict.INSUFFICIENT_COVERAGE, coverage),
        )
    )
    assert receipt.coverage.known_gaps == (code,)
    assert receipt.conclusion is (
        ReceiptConclusion.INSUFFICIENT_COVERAGE
        if resolved
        else ReceiptConclusion.UNRESOLVED_FINDINGS_REMAIN
    )
    assert bool(resolved_finding_ids_for_render(receipt)) is resolved


def test_a_rejection_accepted_row_stops_blocking_only_where_the_receipt_discloses_it() -> None:
    """D8 (issue #905): on an artifact without the terminal sections the row still blocks."""

    finding = _finding()
    base = _context(finding=finding, check=_check(CheckVerdict.NO_ISSUE_DETECTED, _coverage()))
    context = replace(
        base,
        finding_states=(
            ReceiptFindingState(finding.finding_id, resolved=False, rejection_accepted=True),
        ),
    )
    legacy = _build(context)
    assert legacy.conclusion is ReceiptConclusion.UNRESOLVED_FINDINGS_REMAIN
    assert legacy.rejection_accepted_finding_ids == ()

    current_versions = replace(
        _versions(), schema_versions=(SchemaVersionEntry("receipts/receipt-document", "1.3.0"),)
    )
    current = build_receipt(
        context,
        receipt_id("rcp_00000000-0000-4000-8000-000000000001"),
        task_id("tsk_00000000-0000-4000-8000-000000000001"),
        session_id("ses_00000000-0000-4000-8000-000000000001"),
        timestamp_from_string("2026-07-19T00:00:00.000Z"),
        current_versions,
        ReceiptRedactionProfile.FULL_LOCAL,
        ReceiptInclude.FULL,
    )
    assert current.conclusion is not ReceiptConclusion.UNRESOLVED_FINDINGS_REMAIN
    assert current.rejection_accepted_finding_ids == (finding.finding_id,)


@pytest.mark.parametrize(
    ("reason", "phrase"),
    (
        ("unsafe_root", "failed a safety check"),
        ("unsupported_repository", "setup the capture does not read"),
        ("changed_during_capture", "kept changing while it was read"),
        ("git_failed", "a Git command failed or ran out of time"),
        ("repository_mismatch", "named a different repository"),
    ),
)
def test_check_time_change_unavailable_reason_is_a_plain_sentence_in_every_format(
    reason: str, phrase: str
) -> None:
    from finishup.domain.receipts import (
        CHECK_TIME_CHANGE_UNAVAILABLE_GAP,
        check_time_change_unavailable_reason_gap,
    )

    code = check_time_change_unavailable_reason_gap(reason)
    gaps = tuple(sorted((CHECK_TIME_CHANGE_UNAVAILABLE_GAP, code)))
    coverage = _coverage(gaps=gaps)
    receipt = _build(
        _context(
            coverage=coverage,
            gaps=tuple(CaseGap(item, item, ()) for item in gaps),
            check=_check(CheckVerdict.NO_ISSUE_DETECTED, coverage),
        )
    )
    detail = next(gap.detail for gap in receipt.gaps if gap.code == code)
    assert detail is not None and phrase in detail
    wire = receipt_document_to_json(receipt)
    assert wire == receipt_document_to_json(receipt_document_from_json(wire))
    for rendered in (
        str(wire),
        render_receipt_human(receipt, markdown=True),
        render_receipt_human(receipt, markdown=False),
    ):
        assert "The check-time change was unavailable: " in rendered
        assert phrase in rendered


def _single_agent_check(
    coverage: Coverage, *, research_reason: str = "completed"
) -> CheckRecordedPayload:
    """A deterministic-only check of a single-agent run: no coordination records exist."""

    research_outcome = "run" if research_reason == "completed" else "skipped"
    return replace(
        _check(CheckVerdict.NO_ISSUE_DETECTED, coverage),
        policies=(
            PolicyVersion("coordination", "0.1.0"),
            PolicyVersion("research-evidence", "0.1.0"),
            PolicyVersion("work-integrity", "0.1.0"),
        ),
        policy_executions=(
            CheckPolicyExecutionModel(
                policy_id="coordination",
                policy_version="0.1.0",
                outcome="skipped",
                reason="not_applicable",
            ),
            CheckPolicyExecutionModel(
                policy_id="research-evidence",
                policy_version="0.1.0",
                outcome=research_outcome,  # pyright: ignore[reportArgumentType]
                reason=research_reason,  # pyright: ignore[reportArgumentType]
            ),
            CheckPolicyExecutionModel(
                policy_id="work-integrity",
                policy_version="0.1.0",
                outcome="run",
                reason="completed",
            ),
        ),
    )


def test_single_agent_deterministic_run_with_standing_host_gaps_reaches_a_clean_receipt() -> None:
    """#986 (E2): no tb4n1 deterministic receipt could read clean. The coordination pack is
    always ``skipped/not_applicable`` on a single-agent run, and standing host-observation gaps
    a local absence proof tolerates were missing from the receipt's advisory list."""

    from finishup.kernel.deterministic_scope import (
        CLEAN_COMPATIBLE_GAPS,
        DETERMINISTIC_SCOPED_STANDING_GAPS,
    )

    gaps = ("host_outcome_unavailable", "unpaired_event")
    coverage = _coverage(gaps=gaps)
    case_gaps = tuple(CaseGap(code, code, ()) for code in gaps)
    receipt = _build(
        _context(coverage=coverage, gaps=case_gaps, check=_single_agent_check(coverage))
    )
    assert receipt.conclusion is ReceiptConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS
    # The gaps stay disclosed; they only no longer bound the conclusion.
    assert {item.code for item in receipt.gaps} == set(gaps)

    # One list: the receipt and the scoped local verdict read the same clean-compatible gaps.
    assert set(gaps) <= CLEAN_COMPATIBLE_GAPS
    assert DETERMINISTIC_SCOPED_STANDING_GAPS == CLEAN_COMPATIBLE_GAPS | {
        "semantic_review_not_requested"
    }


def test_a_host_gap_the_applicable_check_never_carried_still_bounds_the_receipt() -> None:
    """#986: a host-observation gap is advisory only where the check's counters guarded it."""

    gaps = ("host_outcome_unavailable",)
    receipt_coverage = _coverage(gaps=gaps)
    unguarded = _build(
        _context(
            coverage=receipt_coverage,
            gaps=(CaseGap(gaps[0], gaps[0], ()),),
            check=_single_agent_check(_coverage()),
        )
    )
    assert unguarded.conclusion is ReceiptConclusion.INSUFFICIENT_COVERAGE
    guarded = _build(
        _context(
            coverage=receipt_coverage,
            gaps=(CaseGap(gaps[0], gaps[0], ()),),
            check=_single_agent_check(receipt_coverage),
        )
    )
    assert guarded.conclusion is ReceiptConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS


def test_full_check_completeness_reads_the_same_clean_list() -> None:
    """#986: a policy- or semantic-route check is ``complete`` under the same list, and a
    host-observation gap counts only when the command counters show no unknown outcome."""

    from finishup.application.check import full_check_gaps_clean
    from finishup.kernel.deterministic_scope import CLEAN_COMPATIBLE_GAPS

    clean = {"commands": {"unknown": "0", "live_failed": "0"}}
    unknown = {"commands": {"unknown": "1", "live_failed": "0"}}
    assert full_check_gaps_clean(("unpaired_event", "plan_unrefined_before_first_edit"), clean)
    assert not full_check_gaps_clean(("host_outcome_unavailable",), unknown)
    assert full_check_gaps_clean(("content_unselected",), unknown)
    assert not full_check_gaps_clean(("observation_input_loss",), clean)
    assert not full_check_gaps_clean(("semantic_review_not_requested",), clean)
    assert all(full_check_gaps_clean((code,), clean) for code in sorted(CLEAN_COMPATIBLE_GAPS))


@pytest.mark.parametrize("reason", ("scope_excluded", "material_unavailable"))
def test_a_pack_that_left_roots_unexamined_keeps_the_receipt_bounded(reason: str) -> None:
    """``not_applicable`` means nothing to judge; a scoped or unreadable pack is real loss."""

    coverage = _coverage()
    receipt = _build(
        _context(coverage=coverage, check=_single_agent_check(coverage, research_reason=reason))
    )
    assert receipt.conclusion is ReceiptConclusion.INSUFFICIENT_COVERAGE


def test_a_standing_gap_a_local_proof_does_not_tolerate_still_bounds_the_receipt() -> None:
    code = "observation_input_loss"
    coverage = _coverage(gaps=(code,))
    receipt = _build(
        _context(
            coverage=coverage,
            gaps=(CaseGap(code, code, ()),),
            check=_single_agent_check(coverage),
        )
    )
    assert receipt.conclusion is ReceiptConclusion.INSUFFICIENT_COVERAGE


def test_child_self_verified_finding_reads_self_verified_on_the_parent_receipt() -> None:
    """Issue #984 (ADR-034): a child's self-verified repair is not parent work and never clean."""

    from finishup.domain.coordination import (
        LineageAcceptance,
        LineageOrigin,
        SessionHealth,
        WorkState,
    )
    from finishup.domain.receipts import CHILD_SELF_VERIFIED_NOTE
    from finishup.kernel.lineage import (
        CHILD_SELF_VERIFIED_GAP,
        ChildDependencySnapshot,
        ChildFindingSnapshot,
        LineageManifest,
        evaluate_lineage,
    )
    from finishup.protocol.canonical import JsonValue
    from finishup.protocol.errors import ProtocolValueError
    from finishup.protocol.schemas import validate_schema_instance

    child_task = task_id("tsk_00000000-0000-4000-8000-000000000077")
    child_finding = finding_id("fnd_00000000-0000-4000-8000-000000000077")
    kind = FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS
    snapshot = ChildDependencySnapshot(
        child_task_id=child_task,
        origin=LineageOrigin.PARENT_MINTED,
        acceptance=LineageAcceptance.ACCEPTED,
        work_state=WorkState.CLOSED,
        session_health=SessionHealth.ENDED,
        child_frontier=_FRONTIER,
        child_check_id=_CHECK_EVENT_ID,
        child_receipt_id=receipt_id("rcp_00000000-0000-4000-8000-000000000077"),
        coverage=_coverage(),
        findings=(
            ChildFindingSnapshot(
                finding_id=child_finding,
                kind=kind,
                origin=FindingOrigin.DETERMINISTIC,
                priority=FINDING_KIND_TRAITS[kind][0],
                resolved=False,
                actionable=True,
                self_verified=True,
            ),
        ),
        lineage_authority_revision="rev-1",
        child_check_subject_frontier=_FRONTIER,
        manifest_event_id=_SOURCE_EVENT_ID,
    )
    lineage = evaluate_lineage(LineageManifest((snapshot,)), base_coverage=_coverage())
    assert lineage.actionable_finding_ids == ()
    check = _check(CheckVerdict.NO_ISSUE_DETECTED, lineage.coverage)
    marker = f"lineage:{CHILD_SELF_VERIFIED_GAP}:{child_task}:{_SOURCE_EVENT_ID}"
    context = replace(
        _context(
            check=check,
            coverage=lineage.coverage,
            gaps=(CaseGap(marker, CHILD_SELF_VERIFIED_GAP, (_SOURCE_EVENT_ID,)),),
        ),
        lineage=lineage,
    )
    versions = replace(
        _versions(),
        schema_versions=(SchemaVersionEntry("receipts/receipt-document", "1.3.0"),),
    )
    receipt = build_receipt(
        context,
        receipt_id("rcp_00000000-0000-4000-8000-000000000001"),
        task_id("tsk_00000000-0000-4000-8000-000000000001"),
        session_id("ses_00000000-0000-4000-8000-000000000001"),
        timestamp_from_string("2026-07-19T00:00:00.000Z"),
        versions,
        ReceiptRedactionProfile.FULL_LOCAL,
        ReceiptInclude.FULL,
    )
    # Never clean and never "unresolved findings remain": the parent has nothing to do.
    assert receipt.conclusion is ReceiptConclusion.INSUFFICIENT_COVERAGE
    assert CHILD_SELF_VERIFIED_GAP in receipt.coverage.known_gaps
    (child,) = receipt.children.children
    assert child.outcome == "annotated"
    (row,) = child.findings
    assert (row.self_verified, row.resolved, row.actionable) == (True, False, True)

    wire = receipt_document_to_json(receipt)
    wire_row = cast(dict[str, Any], wire["children"])["children"][0]["findings"][0]
    assert wire_row["self_verified"] is True
    validate_schema_instance("receipt-document", "1.3.0", cast(JsonValue, wire))
    assert receipt_document_from_json(wire) == receipt

    note = f"{child_finding}: {CHILD_SELF_VERIFIED_NOTE}"
    assert (
        CHILD_SELF_VERIFIED_NOTE == "self-verified by the child agent; FinishUP could not prove it"
    )
    assert note in render_receipt_human(receipt, markdown=True)
    assert note in render_receipt_human(receipt, markdown=False)
    assert "1 child finding was self-verified by the child agent" in render_receipt_compact(receipt)

    # An explicit false is not a recorded spelling.
    wire_row["self_verified"] = False
    with pytest.raises(ProtocolValueError):
        receipt_document_from_json(wire)


@pytest.mark.parametrize("resolved", (False, True), ids=("unresolved", "verified_resolved"))
@pytest.mark.parametrize(
    "kind",
    (
        FindingKind.AGENT_CRITERION_UNMET,
        FindingKind.CODE_DEFECT,
        FindingKind.TASK_REQUIREMENT_UNMET,
    ),
)
def test_a_child_review_finding_reaches_the_parent_receipt_under_its_own_kind(
    kind: FindingKind, resolved: bool
) -> None:
    """Issue #1043 (review): a delegated child's AI-powered finding keeps its kind in the
    parent's manifest and JSON receipt, and both stay inside their declared schemas.

    Path: the child's finding -> the coordinator's frozen row -> the recorded
    ``child-dependencies-recorded`` 1.0.0 payload -> the parent's lineage evaluation -> the
    parent's ``receipt-document`` 1.3.0 child section.
    """

    import json

    from builders.dialogue import reviewer_finding
    from builders.policy_cases import evt, finding_record, fnd, obl
    from finishup.application.lineage_coordinator import (
        _child_finding_snapshots,  # pyright: ignore[reportPrivateUsage]
    )
    from finishup.domain.coordination import (
        LineageAcceptance,
        LineageOrigin,
        SessionHealth,
        WorkState,
    )
    from finishup.domain.events import (
        ChildDependenciesRecordedPayload,
        ChildDependencySnapshot,
        EventSchema,
        decode_payload,
    )
    from finishup.domain.values import Actor, actor_id
    from finishup.domain.values import JsonValue as DomainJsonValue
    from finishup.kernel.lineage import evaluate_lineage, lineage_manifest_from_records
    from finishup.protocol.canonical import JsonValue, canonical_encode
    from finishup.protocol.schemas import validate_schema_instance

    # The child: one reviewer finding of ``kind``, open or proved absent by a later check.
    finding = reviewer_finding(1, obl(1), kind=kind)
    child_projection = replace(
        empty_projection_state(),
        frontier=20,
        head_digest=_HEAD,
        findings={
            fnd(1): finding_record(
                finding, 4, resolved_by_check_event_id=evt(9) if resolved else None
            )
        },
    )
    rows = _child_finding_snapshots(child_projection)
    # Never relabelled: the frozen row is the child's own kind.
    assert [(row.kind, row.resolved, row.actionable) for row in rows] == [(kind, resolved, True)]

    # The parent's manifest, as the coordinator records it.
    child_task = task_id("tsk_00000000-0000-4000-8000-000000001043")
    payload = ChildDependenciesRecordedPayload(
        (
            ChildDependencySnapshot(
                child_task_id=child_task,
                origin=LineageOrigin.PARENT_MINTED,
                acceptance=LineageAcceptance.ACCEPTED,
                work_state=WorkState.CLOSED,
                session_health=SessionHealth.ENDED,
                child_frontier=_FRONTIER,
                child_check_id=_CHECK_EVENT_ID,
                child_check_subject_frontier=_FRONTIER,
                child_receipt_id=receipt_id("rcp_00000000-0000-4000-8000-000000001043"),
                coverage=_coverage(),
                findings=rows,
                lineage_authority_revision=1,
            ),
        )
    )
    manifest_wire = json.loads(canonical_encode(cast(JsonValue, encode_payload(payload))))
    assert manifest_wire["children"][0]["findings"][0]["kind"] == kind.value
    validate_schema_instance("child-dependencies-recorded", "1.0.0", manifest_wire)
    schema = EventSchema("child_dependencies_recorded", "1.0.0")
    recorded = decode_payload(schema, cast(DomainJsonValue, manifest_wire))
    assert recorded == payload

    # The parent folds the recorded manifest and builds its JSON receipt.
    manifest = lineage_manifest_from_records(
        (
            SimpleNamespace(
                schema=SimpleNamespace(name="child_dependencies_recorded"),
                event_id=_SOURCE_EVENT_ID,
                ledger=SimpleNamespace(ingestion_sequence=3),
                payload=recorded,
                author=Actor(
                    actor_id("yoetz:observation-coordinator"),
                    ActorType.HARNESS,
                    AuthorshipAssurance.HARNESS_OBSERVED,
                ),
                publication_channel=PublicationChannel.ENGINE_DERIVED,
            ),
        )
    )
    lineage = evaluate_lineage(manifest, base_coverage=_coverage())
    # An open child finding is parent work (the strict lineage reading); a proved-absent one is not.
    assert bool(lineage.actionable_finding_ids) is not resolved
    gaps = tuple(CaseGap(f"lineage:{code}", code, ()) for code in lineage.coverage.known_gaps)
    context = replace(
        _context(
            check=_check(CheckVerdict.NO_ISSUE_DETECTED, lineage.coverage),
            coverage=lineage.coverage,
            gaps=gaps,
        ),
        lineage=lineage,
    )
    versions = replace(
        _versions(),
        schema_versions=(SchemaVersionEntry("receipts/receipt-document", "1.3.0"),),
    )
    receipt = build_receipt(
        context,
        receipt_id("rcp_00000000-0000-4000-8000-000000000001"),
        task_id("tsk_00000000-0000-4000-8000-000000000001"),
        session_id("ses_00000000-0000-4000-8000-000000000001"),
        timestamp_from_string("2026-07-19T00:00:00.000Z"),
        versions,
        ReceiptRedactionProfile.FULL_LOCAL,
        ReceiptInclude.FULL,
    )
    (child,) = receipt.children.children
    (row,) = child.findings
    assert (row.kind, row.resolved, row.actionable) == (kind, resolved, True)
    wire = receipt_document_to_json(receipt)
    wire_row = cast(dict[str, Any], wire["children"])["children"][0]["findings"][0]
    assert wire_row["kind"] == kind.value
    validate_schema_instance("receipt-document", "1.3.0", cast(JsonValue, wire))
    assert receipt_document_from_json(wire) == receipt


def test_a_linked_duplicate_is_disclosed_by_ids_and_never_reads_cleaner() -> None:
    """Issue #996: the duplicate's flags are its earlier finding's; the link is ids only."""

    finding = _finding()
    earlier = finding_id("fnd_00000000-0000-4000-8000-000000000996")
    base = _context(finding=finding, check=_check(CheckVerdict.NO_ISSUE_DETECTED, _coverage()))
    context = replace(
        base,
        finding_states=(
            ReceiptFindingState(
                finding.finding_id, resolved=False, duplicate_of_finding_id=earlier
            ),
        ),
    )
    legacy = _build(context)
    assert legacy.duplicate_finding_links == ()
    current = build_receipt(
        context,
        receipt_id("rcp_00000000-0000-4000-8000-000000000001"),
        task_id("tsk_00000000-0000-4000-8000-000000000001"),
        session_id("ses_00000000-0000-4000-8000-000000000001"),
        timestamp_from_string("2026-07-19T00:00:00.000Z"),
        replace(
            _versions(),
            schema_versions=(SchemaVersionEntry("receipts/receipt-document", "1.3.0"),),
        ),
        ReceiptRedactionProfile.FULL_LOCAL,
        ReceiptInclude.FULL,
    )
    assert [
        (item.finding_id, item.duplicate_of_finding_id) for item in current.duplicate_finding_links
    ] == [(finding.finding_id, earlier)]
    # The earlier finding is open, so the duplicate is too: never a clean conclusion.
    assert current.conclusion is ReceiptConclusion.UNRESOLVED_FINDINGS_REMAIN
    with pytest.raises(ValueError):
        ReceiptFindingState(
            finding.finding_id, resolved=False, duplicate_of_finding_id=finding.finding_id
        )


def test_acknowledged_obligation_is_disclosed_and_never_clean() -> None:
    """Issue #997 (ADR-032 slice C): an obligation the agent will not do caps the conclusion."""

    from finishup.protocol.canonical import JsonValue
    from finishup.protocol.schemas import validate_schema_instance

    obligation = ObligationPublishedPayload(
        obligation_id("obl_00000000-0000-4000-8000-000000000020"),
        "Run focused verification",
        "Recorded successful result",
        ObligationStatus.ACKNOWLEDGED_NOT_DONE,
        acknowledged_not_done_reason="The deployment policy is the task owner's decision.",
    )
    plan = PlanPublishedPayload(1, "Verified task", (obligation.obligation_id,), ())
    context = _context(
        check=_check(CheckVerdict.NO_ISSUE_DETECTED, _coverage()), plan=plan, obligation=obligation
    )
    current = build_receipt(
        context,
        receipt_id("rcp_00000000-0000-4000-8000-000000000001"),
        task_id("tsk_00000000-0000-4000-8000-000000000001"),
        session_id("ses_00000000-0000-4000-8000-000000000001"),
        timestamp_from_string("2026-07-19T00:00:00.000Z"),
        replace(
            _versions(),
            schema_versions=(SchemaVersionEntry("receipts/receipt-document", "1.3.0"),),
        ),
        ReceiptRedactionProfile.FULL_LOCAL,
        ReceiptInclude.FULL,
    )
    assert current.conclusion is ReceiptConclusion.INSUFFICIENT_COVERAGE
    assert current.acknowledged_not_done_obligation_ids == (obligation.obligation_id,)
    wire = receipt_document_to_json(current)
    validate_schema_instance("receipt-document", "1.3.0", cast(JsonValue, wire))
    assert "Obligations acknowledged as not done" in render_receipt_human(current, markdown=True)
    # Counted once (review item 2): not open in the outstanding-work section.
    outstanding = next(
        section for section in current.sections if section.key is ReceiptSectionKey.OUTSTANDING_WORK
    )
    assert "remains open" not in outstanding.body
    assert "1 obligation is acknowledged as not done (not counted as open)." in outstanding.body
    assert obligation.obligation_id not in outstanding.items
    # The reason stays on the obligation; the receipt carries ids only.
    assert "task owner's decision" not in str(wire.get("acknowledged_not_done_obligation_ids"))


def _not_requested_receipt(route_required: bool | None) -> ReceiptDocument:
    from finishup.domain.receipts import SEMANTIC_REVIEW_NOT_REQUESTED_GAP

    coverage = _coverage(gaps=(SEMANTIC_REVIEW_NOT_REQUESTED_GAP,))
    gap = CaseGap(
        f"semantic_outcome:{SEMANTIC_REVIEW_NOT_REQUESTED_GAP}",
        SEMANTIC_REVIEW_NOT_REQUESTED_GAP,
        (),
    )
    check = replace(
        _check(CheckVerdict.NO_ISSUE_DETECTED, coverage, totals=_totals()),
        semantic_route_required=route_required,
    )
    return _build(_context(coverage=coverage, gaps=(gap,), check=check))


_ROUTE_SENTENCE = (
    "The check's route did not require AI-powered review, so its absence is disclosed and does "
    "not bound the conclusion."
)


def test_a_route_without_required_review_makes_not_requested_a_disclosure() -> None:
    """Issue #986 (owner decision E2, "record route; don't block")."""

    receipt = _not_requested_receipt(False)
    assert receipt.conclusion is ReceiptConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS
    # Disclosed, never dropped.
    assert "semantic_review_not_requested" in receipt.coverage.known_gaps
    assert "semantic_review_not_requested" in {item.code for item in receipt.gaps}
    for markdown in (True, False):
        rendered = render_receipt_human(receipt, markdown=markdown)
        assert "AI-powered review was not requested (local-only check)." in rendered
        assert _ROUTE_SENTENCE in rendered


@pytest.mark.parametrize("route_required", (None, True))
def test_a_requiring_or_unrecorded_route_keeps_not_requested_blocking(
    route_required: bool | None,
) -> None:
    """Issue #986: an old check (no field) or a requiring route reads exactly as before."""

    receipt = _not_requested_receipt(route_required)
    assert receipt.conclusion is ReceiptConclusion.INSUFFICIENT_COVERAGE
    for markdown in (True, False):
        assert _ROUTE_SENTENCE not in render_receipt_human(receipt, markdown=markdown)


def test_a_route_record_never_excuses_a_carried_review_attempt_gap() -> None:
    """Issue #986: only the not-requested code is tolerated; a refused review still bounds."""

    from finishup.domain.receipts import SEMANTIC_REVIEW_NOT_REQUESTED_GAP

    gaps = ("semantic_relevance_review_not_run", SEMANTIC_REVIEW_NOT_REQUESTED_GAP)
    coverage = _coverage(gaps=gaps)
    check = replace(
        _check(CheckVerdict.INSUFFICIENT_COVERAGE, coverage, totals=_totals()),
        semantic_route_required=False,
    )
    receipt = _build(
        _context(
            coverage=coverage,
            gaps=tuple(CaseGap(code, code, ()) for code in gaps),
            check=check,
        )
    )
    assert receipt.conclusion is ReceiptConclusion.INSUFFICIENT_COVERAGE


def test_check_event_route_record_round_trips_and_old_events_replay_unchanged() -> None:
    """Issue #986: optional on check_recorded 1.4.0 only; events without it keep their bytes."""

    from finishup.domain.events import (
        CHECK_EVENT_SCHEMA_VERSION,
        REVIEW_CHECK_EVENT_SCHEMA_VERSION,
        EventSchema,
        decode_payload,
        encode_payload,
    )
    from finishup.protocol.canonical import canonical_encode

    schema = EventSchema("check_recorded", REVIEW_CHECK_EVENT_SCHEMA_VERSION)
    old = _check(
        CheckVerdict.NO_ISSUE_DETECTED,
        _coverage(gaps=("semantic_review_not_requested",)),
        totals=_totals(),
    )
    old_wire = encode_payload(old)
    assert isinstance(old_wire, Mapping)
    assert "semantic_route_required" not in old_wire
    decoded_old = decode_payload(schema, old_wire)
    assert isinstance(decoded_old, CheckRecordedPayload)
    assert decoded_old.semantic_route_required is None
    # Replay re-encodes an old event to the identical bytes and the identical conclusion.
    assert canonical_encode(encode_payload(decoded_old)) == canonical_encode(old_wire)
    assert _not_requested_receipt(None) == _not_requested_receipt(None)

    recorded = replace(old, semantic_route_required=False)
    wire = encode_payload(recorded)
    assert isinstance(wire, Mapping)
    assert wire["semantic_route_required"] is False
    assert decode_payload(schema, wire) == recorded
    # Never on an older plain-check schema, and never a non-boolean.
    plain = replace(recorded, totals=None)
    with pytest.raises(ValueError):
        decode_payload(
            EventSchema("check_recorded", CHECK_EVENT_SCHEMA_VERSION), encode_payload(plain)
        )
    with pytest.raises(ValueError):
        replace(old, semantic_route_required=cast(Any, 0))


# Issue #1017 (owner decision, audit A-4): a gap an earlier check carried that a later check no
# longer carries stays on the receipt as ``historical`` and never lowers the conclusion. Mirrors the
# tb4n2 cargo-flight-dispatch receipt, where a retained finding's coverage carried
# ``planned_verification_not_observed`` after the latest check had cleared it.
_CLEARED_GAP = "planned_verification_not_observed"
_CLEARED_AT = Frontier(1, _DIGEST)


def _historical_receipt(*, historical: bool, schema_version: str = "1.3.0") -> ReceiptDocument:
    check = _check(CheckVerdict.NO_ISSUE_DETECTED, _coverage())
    context = _context(
        check=check,
        coverage=_coverage(gaps=(_CLEARED_GAP,)),
        gaps=(CaseGap(f"retained_finding_coverage:{_CLEARED_GAP}", _CLEARED_GAP, ()),),
    )
    if historical:
        context = replace(context, historical_gaps=((_CLEARED_GAP, _CLEARED_AT),))
    versions = replace(
        _versions(),
        schema_versions=(SchemaVersionEntry("receipts/receipt-document", schema_version),),
    )
    return build_receipt(
        context,
        receipt_id("rcp_00000000-0000-4000-8000-000000000001"),
        task_id("tsk_00000000-0000-4000-8000-000000000001"),
        session_id("ses_00000000-0000-4000-8000-000000000001"),
        timestamp_from_string("2026-07-19T00:00:00.000Z"),
        versions,
        ReceiptRedactionProfile.FULL_LOCAL,
        ReceiptInclude.FULL,
    )


def test_cleared_gap_is_historical_and_never_lowers_the_conclusion() -> None:
    from finishup.domain.receipts import (
        HISTORICAL_GAPS_SECTION_TITLE,
        ReceiptGapStatus,
        historical_receipt_gaps,
        live_receipt_gap_codes,
    )
    from finishup.protocol.canonical import JsonValue
    from finishup.protocol.schemas import validate_schema_instance

    receipt = _historical_receipt(historical=True)
    # The conclusion equals a receipt that never carried the gap at all.
    baseline = _build(_context(check=_check(CheckVerdict.NO_ISSUE_DETECTED, _coverage())))
    assert baseline.conclusion is ReceiptConclusion.NO_UNRESOLVED_DETERMINISTIC_FINDINGS
    assert receipt.conclusion is baseline.conclusion
    # The document keeps the full coverage union; the gap row says it is history.
    assert receipt.coverage.known_gaps == (_CLEARED_GAP,)
    (gap,) = receipt.gaps
    assert (gap.code, gap.status, gap.cleared_at_frontier) == (
        _CLEARED_GAP,
        ReceiptGapStatus.HISTORICAL,
        _CLEARED_AT,
    )
    assert historical_receipt_gaps(receipt) == (gap,)
    assert live_receipt_gap_codes(receipt) == ()
    # The limitations section lists no current limitation.
    sections = {section.key: section for section in receipt.sections}
    limitations = sections[ReceiptSectionKey.LIMITATIONS_AND_COVERAGE]
    assert limitations.items == ()
    assert _CLEARED_GAP not in limitations.body

    wire = receipt_document_to_json(receipt)
    wire_gap = cast(dict[str, Any], wire["gaps"][0])  # pyright: ignore[reportIndexIssue]
    assert wire_gap["status"] == "historical"
    assert wire_gap["cleared_at_frontier"] == {"sequence": "1", "head_digest": _DIGEST}
    validate_schema_instance("receipt-document", "1.3.0", cast(JsonValue, wire))
    assert receipt_document_from_json(wire) == receipt

    markdown = render_receipt_human(receipt, markdown=True)
    text = render_receipt_human(receipt, markdown=False)
    assert f"## {HISTORICAL_GAPS_SECTION_TITLE}" in markdown
    assert f"- `{_CLEARED_GAP}`: cleared at frontier 1; no action needed." in markdown
    assert f"\n{HISTORICAL_GAPS_SECTION_TITLE}\n" in text
    assert f"- {_CLEARED_GAP}: cleared at frontier 1; no action needed." in text
    # The live repair sentence is never repeated for a cleared gap (Codex review round 3).
    assert "causal_parents" not in markdown.split(HISTORICAL_GAPS_SECTION_TITLE, 1)[1]
    assert "not current limitations" in text
    compact = render_receipt_compact(receipt)
    assert "no unresolved local findings were recorded" in compact


def test_gap_the_latest_check_still_carries_stays_live() -> None:
    from finishup.domain.receipts import HISTORICAL_GAPS_SECTION_TITLE, ReceiptGapStatus

    receipt = _historical_receipt(historical=False)
    assert receipt.conclusion is ReceiptConclusion.INSUFFICIENT_COVERAGE
    (gap,) = receipt.gaps
    assert (gap.status, gap.cleared_at_frontier) == (ReceiptGapStatus.LIVE, None)
    wire_gap = cast(dict[str, Any], receipt_document_to_json(receipt)["gaps"][0])  # pyright: ignore[reportIndexIssue]
    assert "status" not in wire_gap and "cleared_at_frontier" not in wire_gap
    sections = {section.key: section for section in receipt.sections}
    assert sections[ReceiptSectionKey.LIMITATIONS_AND_COVERAGE].items == (_CLEARED_GAP,)
    assert HISTORICAL_GAPS_SECTION_TITLE not in render_receipt_human(receipt, markdown=True)


def test_earlier_receipt_artifact_keeps_every_gap_live() -> None:
    from finishup.domain.receipts import ReceiptGapStatus

    receipt = _historical_receipt(historical=True, schema_version="1.0.0")
    assert receipt.conclusion is ReceiptConclusion.INSUFFICIENT_COVERAGE
    assert all(gap.status is ReceiptGapStatus.LIVE for gap in receipt.gaps)


def test_historical_gap_context_must_name_a_known_gap() -> None:
    context = _context(check=_check(CheckVerdict.NO_ISSUE_DETECTED, _coverage()))
    with pytest.raises(ValueError, match="receipt_build_context_invalid"):
        replace(context, historical_gaps=((_CLEARED_GAP, _CLEARED_AT),))


def _check_record(sequence: int, gaps: tuple[str, ...]) -> Any:
    payload = replace(
        _check(CheckVerdict.NO_ISSUE_DETECTED, _coverage(gaps=gaps)),
        subject_frontier=Frontier(sequence, _DIGEST),
    )
    return SimpleNamespace(payload=payload, ledger=SimpleNamespace(ingestion_sequence=sequence))


def test_application_names_the_first_check_that_no_longer_carried_the_gap() -> None:
    from finishup.application.receipt import (
        _historical_gaps,  # pyright: ignore[reportPrivateUsage]
    )

    other = SimpleNamespace(payload=None, ledger=SimpleNamespace(ingestion_sequence=4))
    first = _check_record(3, (_CLEARED_GAP, "unpaired_event"))
    second = _check_record(5, (_CLEARED_GAP,))
    clearing = _check_record(8, ())
    latest = _check_record(11, ())
    records = cast(Any, (first, other, second, clearing, latest))
    # Cleared at the subject frontier of the first check after the last one that carried it.
    assert _historical_gaps(records, latest, {_CLEARED_GAP}) == (
        (_CLEARED_GAP, Frontier(8, _DIGEST)),
    )
    # A code the latest check still carries stays live; one no check ever carried stays live.
    carrying = _check_record(11, (_CLEARED_GAP,))
    assert _historical_gaps(cast(Any, (first, carrying)), carrying, {_CLEARED_GAP}) == ()
    assert _historical_gaps(records, latest, {"cursor_stale"}) == ()
    # Checks after the latest tested check never decide; no latest check, nothing historical.
    assert _historical_gaps(cast(Any, (first, latest, clearing)), first, {_CLEARED_GAP}) == ()
    assert _historical_gaps(records, None, {_CLEARED_GAP}) == ()
    # Deterministic: replaying the same records gives the same answer in any input order.
    assert _historical_gaps(cast(Any, tuple(reversed(records))), latest, {_CLEARED_GAP}) == (
        (_CLEARED_GAP, Frontier(8, _DIGEST)),
    )


def test_result_coverage_and_every_surface_count_live_gaps_only() -> None:
    from finishup.application.receipt import (
        _internal_result,  # pyright: ignore[reportPrivateUsage]
    )
    from finishup.cli.render import render_human_receipt
    from finishup.domain.receipts import historical_gaps_from_wire
    from finishup.mcp.summaries import summary_for_receipt
    from finishup.protocol.models import CoverageModel, ReceiptFormat, ReceiptSuccessModel

    receipt = _historical_receipt(historical=True)
    for output_format in (ReceiptFormat.JSON, ReceiptFormat.MARKDOWN, ReceiptFormat.TEXT):
        request = SimpleNamespace(
            format=output_format,
            request_id="req_00000000-0000-4000-8000-000000000001",
            redaction_profile=ReceiptRedactionProfile.FULL_LOCAL,
            include=ReceiptInclude.FULL,
            writer_id=None,
        )
        result = _internal_result(
            cast(Any, request),
            receipt,
            cast(Any, SimpleNamespace(object_id="obj_00000000-0000-4000-8000-000000000001")),
            "sha256:" + "3" * 64,
            _FRONTIER,
        )
        # The result's coverage names no current limitation; the document keeps the union.
        assert result.coverage.known_gaps == ()
        assert receipt.coverage.known_gaps == (_CLEARED_GAP,)
        envelope = result.as_json()
        summary = summary_for_receipt(envelope)
        assert "coverage limitations: 0;" in summary
        assert f"gap codes: {_CLEARED_GAP}" not in summary
        fields: dict[str, Any] = {
            **envelope,
            "coverage": CoverageModel.model_validate(envelope["coverage"]),
        }
        success = ReceiptSuccessModel.model_construct(**fields)
        cli = render_human_receipt(success)
        assert "Limitations: none declared" in cli
        if output_format is ReceiptFormat.JSON:
            assert historical_gaps_from_wire(envelope["document"]) == ((_CLEARED_GAP, "1"),)
            assert f"cleared earlier (historical, not limitations): {_CLEARED_GAP} at 1;" in (
                summary
            )
            assert (
                f"Cleared earlier (historical, not a current limitation): {_CLEARED_GAP} "
                "(cleared at frontier 1)"
            ) in cli
        else:
            assert f"{_CLEARED_GAP}" in cast(str, result.human_text)
            assert "Cleared earlier (historical)" in cli
    # A malformed wire row is skipped, never echoed.
    assert historical_gaps_from_wire({"gaps": [{"code": "x y", "status": "historical"}]}) == ()


def test_claim_verification_pairing_renders_in_json_markdown_and_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The pairing is prose in the evidence section. Compact wording stays frozen (#1079)."""

    from finishup.kernel.claim_verification import CLAIM_VERIFICATION_HEADER

    header = CLAIM_VERIFICATION_HEADER
    line = (
        "obl_00000000-0000-4000-8000-0000000000c2 "
        "requested_item_never_attempted no_verification_limit"
    )
    context = _context(check=_check(CheckVerdict.NO_ISSUE_DETECTED, _coverage()))
    plain = _build(context)
    evidence = next(
        section
        for section in plain.sections
        if section.key is ReceiptSectionKey.EVIDENCE_AND_CLAIM_BASIS
    )
    assert header not in evidence.body
    assert header not in render_receipt_compact(plain)

    def _paired(_projection: object, _records: object) -> tuple[tuple[str, ...], str]:
        return ((header, line), "")

    monkeypatch.setattr(
        "finishup.kernel.receipt_builder.claim_verification_report",
        _paired,
    )
    receipt = _build(context)
    evidence = next(
        section
        for section in receipt.sections
        if section.key is ReceiptSectionKey.EVIDENCE_AND_CLAIM_BASIS
    )
    assert header in evidence.body
    assert line in evidence.body
    encoded = str(receipt_document_to_json(receipt))
    assert header in encoded
    assert line in encoded
    assert header in render_receipt_human(receipt, markdown=True)
    assert line in render_receipt_human(receipt, markdown=False)
    assert header not in render_receipt_compact(receipt)


def test_a_holed_projection_omits_claim_pairing_and_names_the_limit() -> None:
    """A redacted obligation must not raise the receipt. Pairing is omitted; the limitation
    names only the obligation id, in JSON, markdown and text. Compact wording stays frozen."""

    from finishup.kernel.claim_verification import CLAIM_VERIFICATION_HEADER

    obligation = ObligationPublishedPayload(
        obligation_id("obl_00000000-0000-4000-8000-0000000000c2"),
        "Deliver the requested outcome",
        "A recorded run",
        ObligationStatus.RESOLVED,
        resolution_evidence_refs=(result_id("res_00000000-0000-4000-8000-0000000000c2"),),
    )
    plan = PlanPublishedPayload(1, "Verified task", (obligation.obligation_id,), ())
    receipt = _build(
        _context(
            check=_check(CheckVerdict.NO_ISSUE_DETECTED, _coverage()),
            plan=plan,
            obligation=obligation,
            obligation_redacted=True,
        )
    )
    sentence = f"The claim-verification pairing could not be read for {obligation.obligation_id}."
    limitations = next(
        section
        for section in receipt.sections
        if section.key is ReceiptSectionKey.LIMITATIONS_AND_COVERAGE
    )
    evidence = next(
        section
        for section in receipt.sections
        if section.key is ReceiptSectionKey.EVIDENCE_AND_CLAIM_BASIS
    )
    assert sentence in limitations.body
    assert CLAIM_VERIFICATION_HEADER not in evidence.body
    assert "Deliver the requested outcome" not in limitations.body
    encoded = str(receipt_document_to_json(receipt))
    assert sentence in encoded
    assert sentence in render_receipt_human(receipt, markdown=True)
    assert sentence in render_receipt_human(receipt, markdown=False)
    assert sentence not in render_receipt_compact(receipt)


def test_an_unchanged_coordinator_failure_is_named_on_the_receipt() -> None:
    """An unchanged coordinator failure is one receipt sentence, the same fault sentence as #1077.

    The readiness checklist, not a second limitations sentence, says not to send that check again.
    """

    from finishup.domain.receipts import COORDINATOR_FAILURE_LIMITATION
    from finishup.protocol.readiness_text import COORDINATOR_FAILURE_SENTENCE

    check = replace(
        _check(CheckVerdict.NO_ISSUE_DETECTED, _coverage()),
        semantic_status=SemanticStatus.FAILED,
        semantic_reason=SemanticReason.COORDINATOR_FAILURE,
        semantic_provenance=None,
    )
    receipt = _build(_context(check=check))
    limitations = next(
        section
        for section in receipt.sections
        if section.key is ReceiptSectionKey.LIMITATIONS_AND_COVERAGE
    )
    rendered = render_receipt_human(receipt, markdown=False)
    assert limitations.body.count(COORDINATOR_FAILURE_LIMITATION) == 1
    assert rendered.count(COORDINATOR_FAILURE_LIMITATION) == 1
    assert COORDINATOR_FAILURE_SENTENCE not in limitations.body
    assert COORDINATOR_FAILURE_SENTENCE not in rendered
