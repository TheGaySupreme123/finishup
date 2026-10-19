"""#1118 R6: the reviewer's final advisory and residual reasons reach every receipt rendering.

The applicable check's recorded review summary travels as one fenced receipt item under the
``full_local`` profile, and as an explicit, counted omission under the export profiles. It never
enters the structural version-and-policy sentence.
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from finishup.domain.events import MissingForAssessmentItem
from finishup.domain.findings import CheckVerdict
from finishup.domain.receipts import (
    ReceiptDocument,
    ReceiptRedactionCategory,
    ReceiptRedactionReason,
    ReceiptSectionKey,
    receipt_document_to_json,
    render_receipt_human,
)
from finishup.kernel.receipt_builder import REVIEWER_ADVISORY_LABEL
from finishup.protocol.models import ReceiptRedactionProfile, SemanticReason, SemanticStatus
from unit.kernel import test_receipt_builder as receipt_test

_REASON = "RECEIPT_RESIDUAL_SENTINEL: identify the exact command."


def _document(profile: ReceiptRedactionProfile) -> ReceiptDocument:
    check = replace(
        receipt_test._check(  # pyright: ignore[reportPrivateUsage]
            CheckVerdict.INSUFFICIENT_COVERAGE,
            receipt_test._coverage(gaps=("semantic_packet_insufficient",)),  # pyright: ignore[reportPrivateUsage]
            semantic_conclusion="insufficient_packet",
            semantic_provenance=receipt_test._provenance(),  # pyright: ignore[reportPrivateUsage]
            missing_for_assessment=(
                MissingForAssessmentItem(
                    "command_identity", (), "structurally_unavailable_on_this_host"
                ),
            ),
        ),
        semantic_status=SemanticStatus.SUCCEEDED,
        semantic_reason=SemanticReason.SEMANTIC_COMPLETED,
        review_summary="What the reviewer still needs: " + _REASON,
    )
    context = receipt_test._context(  # pyright: ignore[reportPrivateUsage]
        check=check,
        coverage=check.coverage,
        gaps=(
            receipt_test.CaseGap(
                "semantic_packet_insufficient", "semantic_packet_insufficient", ()
            ),
        ),
    )
    return receipt_test._build(context, profile=profile)  # pyright: ignore[reportPrivateUsage]


def _rendered(document: ReceiptDocument, format: str) -> str:
    if format == "json":
        return json.dumps(receipt_document_to_json(document), default=dict)
    return render_receipt_human(document, markdown=format == "markdown")


@pytest.mark.parametrize("format", ["json", "markdown", "text"])
def test_a_full_local_receipt_carries_the_reviewers_residual_reason_fenced(format: str) -> None:
    document = _document(ReceiptRedactionProfile.FULL_LOCAL)
    rendered = _rendered(document, format)
    assert _REASON in rendered
    assert REVIEWER_ADVISORY_LABEL + "What the reviewer still needs" in rendered
    sections = {section.key: section for section in document.sections}
    limitations = sections[ReceiptSectionKey.LIMITATIONS_AND_COVERAGE]
    assert limitations.items[-1].startswith(REVIEWER_ADVISORY_LABEL)
    # Model text stays out of every structural sentence and section body.
    assert all(_REASON not in section.body for section in document.sections)


@pytest.mark.parametrize(
    "profile",
    [ReceiptRedactionProfile.DEFAULT_LOCAL_EXPORT, ReceiptRedactionProfile.REDACTED_SHARE],
)
@pytest.mark.parametrize("format", ["json", "markdown", "text"])
def test_an_export_receipt_says_the_reviewer_summary_was_withheld(
    profile: ReceiptRedactionProfile, format: str
) -> None:
    document = _document(profile)
    rendered = _rendered(document, format)
    assert _REASON not in rendered
    assert f"AI-powered reviewer summary withheld by this receipt's {profile.value}" in rendered
    redactions = {(row.category, row.reason): row.count for row in document.redactions}
    key = (ReceiptRedactionCategory.FINDING_DETAIL, ReceiptRedactionReason.POLICY_REDACTED)
    assert redactions.get(key, 0) >= 1
