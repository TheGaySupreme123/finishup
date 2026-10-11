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
