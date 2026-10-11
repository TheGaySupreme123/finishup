"""A receipt past the document's row and section bounds still builds (tb4n3 RC-2, #1025, A6).

The receipt document holds at most 100 rows of a kind, 64 gaps and 64 items a section. A task that
carried more than that failed to produce any receipt: the build raised `invalid_receipt_document`
(INVALID_REQUEST "The receipt request is invalid") or a selection guard (STORAGE_CORRUPT), and the
agent could never close the task. The builder now keeps the rows that matter most and says how many
it left out.
"""

from __future__ import annotations

from dataclasses import replace

from tests.unit.kernel.test_receipt_builder import (
    _CHECK_EVENT_ID,  # pyright: ignore[reportPrivateUsage]
    _FRONTIER,  # pyright: ignore[reportPrivateUsage]
    _HEAD,  # pyright: ignore[reportPrivateUsage]
    _SOURCE_EVENT_ID,  # pyright: ignore[reportPrivateUsage]
    _build,  # pyright: ignore[reportPrivateUsage]
    _check,  # pyright: ignore[reportPrivateUsage]
    _coverage,  # pyright: ignore[reportPrivateUsage]
    _finding,  # pyright: ignore[reportPrivateUsage]
    _versions,  # pyright: ignore[reportPrivateUsage]
)
from tests.unit.kernel.test_receipt_builder import (
    _context as _single_context,  # pyright: ignore[reportPrivateUsage]
)

from yoetz.domain.events import encode_payload
from yoetz.domain.findings import CheckVerdict, Finding, rank_key
from yoetz.domain.receipts import (
    ReceiptConclusion,
    ReceiptSectionKey,
    receipt_document_from_json,
    receipt_document_to_json,
)
from yoetz.domain.values import finding_id, obligation_id
from yoetz.kernel.deterministic_checks import CaseAvailabilityFacts
from yoetz.kernel.projections import (
    FindingProjectionRecord,
    LatestTestedState,
    empty_projection_state,
)
from yoetz.kernel.receipt_builder import (
    ReceiptBuildContext,
    ReceiptFindingState,
    _finish_section,  # pyright: ignore[reportPrivateUsage]
    _keep_by_rank,  # pyright: ignore[reportPrivateUsage]
)
from yoetz.protocol.canonical import canonical_digest
from yoetz.protocol.coverage import LedgerFreshness


def _many_findings(count: int) -> tuple[Finding, ...]:
    base = _finding()
    findings = tuple(
        replace(
            base,
            finding_id=finding_id(f"fnd_00000000-0000-4000-8000-{index:012d}"),
            summary=f"Obligation {index} remains open.",
            subject_refs=(obligation_id(f"obl_00000000-0000-4000-8000-{index:012d}"),),
        )
        for index in range(1, count + 1)
    )
    return tuple(sorted(findings, key=rank_key))


def _context(findings: tuple[Finding, ...], resolved: frozenset[str]) -> ReceiptBuildContext:
    check = _check(
        CheckVerdict.ACTION_REQUIRED,
        _coverage(),
        returned=tuple(
            finding.finding_id for finding in findings if finding.finding_id not in resolved
        )[:10],
    )
    records = {
        finding.finding_id: FindingProjectionRecord(
            payload=finding,
            payload_digest=canonical_digest(encode_payload(finding)),
            redacted=False,
            source_event_id=_SOURCE_EVENT_ID,
            source_frontier=1,
        )
        for finding in findings
    }
    projection = replace(
        empty_projection_state(),
        frontier=2,
        head_digest=_HEAD,
        findings=records,
        latest_tested_state=LatestTestedState(
            source_check_event_id=_CHECK_EVENT_ID,
            subject_frontier=check.subject_frontier,
            verdict=check.verdict,
            returned_finding_ids=check.returned_finding_ids,
            suppressed_count=0,
            coverage=check.coverage,
        ),
        freshness=LedgerFreshness.CURRENT,
    )
    return ReceiptBuildContext(
        projection=projection,
        subject_frontier=_FRONTIER,
        availability=CaseAvailabilityFacts(),
        coverage=_coverage(),
        gaps=(),
        finding_states=tuple(
            ReceiptFindingState(finding.finding_id, resolved=finding.finding_id in resolved)
            for finding in findings
        ),
        applicable_check=check,
    )


def test_more_than_a_hundred_findings_build_with_the_unresolved_ones_first() -> None:
    findings = _many_findings(130)
    resolved = frozenset(finding.finding_id for finding in findings[:40])
    receipt = _build(_context(findings, resolved))

    assert receipt.conclusion is ReceiptConclusion.UNRESOLVED_FINDINGS_REMAIN
    assert len(receipt.findings) == 100
    kept = {finding.finding_id for finding in receipt.findings}
    unresolved = {finding.finding_id for finding in findings} - resolved
    # Every unresolved actionable finding is carried before any resolved history row.
    assert unresolved <= kept
    assert len(kept & resolved) == 100 - len(unresolved)
    summary = next(
        section for section in receipt.sections if section.key is ReceiptSectionKey.SUMMARY
    )
    assert "30 findings" in summary.body
    assert "status lists every row" in summary.body
    # The bounded summary items never exceed the section bound, and the rest are counted.
    assert len(summary.items) <= 64
    # A bounded receipt is still a valid, round-tripping document.
    again = receipt_document_from_json(receipt_document_to_json(receipt))
    assert again == receipt


def test_a_section_past_its_item_bound_counts_the_rest_instead_of_failing() -> None:
    items = tuple(f"fnd_00000000-0000-4000-8000-{index:012d}" for index in range(1, 101))
    body, kept = _finish_section("Findings remain.", items)
    assert len(kept) == 64 and kept == items[:64]
    assert "36 more item(s) are not listed here" in body


def test_a_section_body_past_its_text_bound_is_cut_with_a_visible_marker() -> None:
    body, _ = _finish_section("x" * 40_000, ())
    assert len(body) <= 32_768
    assert body.endswith("[section text cut]")


def test_keep_by_rank_is_stable_and_counts_what_it_left_out() -> None:
    values = tuple(range(10))
    kept, omitted = _keep_by_rank(values, 4, lambda value: 0 if value % 3 == 0 else 1)
    assert kept == (0, 3, 6, 9)
    assert omitted == 6
    assert _keep_by_rank(values, 10, lambda value: value) == (values, 0)


def test_a_child_with_more_findings_than_a_receipt_child_holds_still_builds() -> None:
    """Lineage allows 100 findings per child; a receipt child outcome holds 64 (A6)."""

    from dataclasses import replace as dc_replace

    from yoetz.domain.coordination import (
        LineageAcceptance,
        LineageOrigin,
        SessionHealth,
        WorkState,
    )
    from yoetz.domain.findings import FINDING_KIND_TRAITS, FindingKind, FindingOrigin
    from yoetz.domain.receipts import SchemaVersionEntry
    from yoetz.domain.values import receipt_id, session_id, task_id, timestamp_from_string
    from yoetz.kernel.lineage import (
        ChildDependencySnapshot,
        ChildFindingSnapshot,
        LineageManifest,
        evaluate_lineage,
    )
    from yoetz.kernel.receipt_builder import build_receipt
    from yoetz.protocol.models import ReceiptInclude, ReceiptRedactionProfile

    kind = FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS
    rows = tuple(
        ChildFindingSnapshot(
            finding_id=finding_id(f"fnd_00000000-0000-4000-8000-{index:012d}"),
            kind=kind,
            origin=FindingOrigin.DETERMINISTIC,
            priority=FINDING_KIND_TRAITS[kind][0],
            resolved=index > 5,
            resolution_event_id=_CHECK_EVENT_ID if index > 5 else None,
            actionable=True,
            self_verified=False,
        )
        for index in range(1, 101)
    )
    snapshot = ChildDependencySnapshot(
        child_task_id=task_id("tsk_00000000-0000-4000-8000-000000000077"),
        origin=LineageOrigin.PARENT_MINTED,
        acceptance=LineageAcceptance.ACCEPTED,
        work_state=WorkState.CLOSED,
        session_health=SessionHealth.ENDED,
        child_frontier=_FRONTIER,
        child_check_id=_CHECK_EVENT_ID,
        child_receipt_id=receipt_id("rcp_00000000-0000-4000-8000-000000000077"),
        coverage=_coverage(),
        findings=rows,
        lineage_authority_revision="rev-1",
        child_check_subject_frontier=_FRONTIER,
        manifest_event_id=_SOURCE_EVENT_ID,
    )
    lineage = evaluate_lineage(LineageManifest((snapshot,)), base_coverage=_coverage())
    from yoetz.kernel.deterministic_checks import CaseGap

    marker = f"lineage:lineage_child_actionable_finding:{snapshot.child_task_id}:{_SOURCE_EVENT_ID}"
    context = dc_replace(
        _single_context(
            check=_check(CheckVerdict.ACTION_REQUIRED, lineage.coverage),
            coverage=lineage.coverage,
            gaps=(CaseGap(marker, "lineage_child_actionable_finding", (_SOURCE_EVENT_ID,)),),
        ),
        lineage=lineage,
    )
    versions = dc_replace(
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
    assert len(child.findings) == 64
    kept = {row.finding_id for row in child.findings}
    # Every unresolved actionable child finding is kept before any resolved history row.
    assert {row.finding_id for row in rows[:5]} <= kept
    summary = next(
        section for section in receipt.sections if section.key is ReceiptSectionKey.SUMMARY
    )
    assert "36 child findings" in summary.body
