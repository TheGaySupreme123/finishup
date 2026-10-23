"""Evidence pointers use typed readiness or the canonical receipt evidence section only."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from finishup.mcp.summaries import (
    MAX_SUMMARY_BYTES,
    summary_for_check,
    summary_for_receipt,
    summary_for_status,
)

_MARKER = "Recorded evidence links: status view=obligations."
_PRIVATE = "private participant content must stay out of compact summaries"
_BUILDERS = (summary_for_check, summary_for_status, summary_for_receipt)


def _envelope() -> dict[str, object]:
    return {
        "verdict": "no_issue_detected",
        "semantic_status": "not_requested",
        "semantic_reason": "deterministic_mode",
        "view": "compact",
        "conclusion": "insufficient_coverage",
        "coverage": {"known_gaps": []},
        "suppressed_finding_count": "0",
        "frontier": {"sequence": "4", "head_digest": "sha256:" + "ab" * 32},
    }


@pytest.mark.parametrize("builder", _BUILDERS)
@pytest.mark.parametrize("basis", [None, "", True, 1, [_PRIVATE], {"text": _PRIVATE}, _PRIVATE])
def test_readiness_pointer_requires_a_nonempty_string(
    builder: Callable[[object], str],
    basis: object,
) -> None:
    envelope = _envelope()
    envelope["closure_readiness"] = {"evidence_basis_summary": basis}
    text = builder(envelope)
    assert ("Evidence links:" in text) is (isinstance(basis, str) and bool(basis))
    assert _PRIVATE not in text
    assert len(text.encode("utf-8")) <= MAX_SUMMARY_BYTES


@pytest.mark.parametrize("builder", _BUILDERS)
@pytest.mark.parametrize(
    ("section", "has_pointer"),
    [
        ({"key": "evidence_and_claim_basis", "body": _MARKER + " " + _PRIVATE}, True),
        ({"key": "findings_and_dispositions", "body": _MARKER}, False),
        ({"body": _MARKER}, False),
        ({"key": "evidence_and_claim_basis", "body": [_MARKER]}, False),
        ({"key": "evidence_and_claim_basis", "body": True}, False),
        ({"key": "evidence_and_claim_basis", "body": _MARKER[:-1]}, False),
        ({"key": "evidence_and_claim_basis", "body": "Legacy receipt evidence."}, False),
    ],
)
def test_receipt_fallback_requires_the_canonical_section_and_exact_sentence(
    builder: Callable[[object], str],
    section: dict[str, object],
    has_pointer: bool,
) -> None:
    envelope = _envelope()
    envelope["document"] = {"sections": [section]}
    text = builder(envelope)
    assert ("Evidence links:" in text) is has_pointer
    assert _PRIVATE not in text
    assert len(text.encode("utf-8")) <= MAX_SUMMARY_BYTES


@pytest.mark.parametrize("builder", _BUILDERS)
def test_legacy_result_without_an_evidence_basis_keeps_its_summary(
    builder: Callable[[object], str],
) -> None:
    envelope = _envelope()
    legacy = builder(envelope)
    envelope["closure_readiness"] = {"evidence_basis_summary": ""}
    envelope["document"] = {"sections": []}
    assert builder(envelope) == legacy
