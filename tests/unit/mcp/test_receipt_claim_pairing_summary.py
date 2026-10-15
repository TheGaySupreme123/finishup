"""The MCP receipt summary keeps the claim-verification pairing inside a tight byte cap."""

from __future__ import annotations

import pytest

from finishup.kernel.claim_verification import CLAIM_VERIFICATION_HEADER
from finishup.mcp import summaries
from finishup.mcp.summaries import summary_for_receipt

_OBLIGATION = "obl_00000000-0000-4000-8000-0000000000c2"
_RESULT = "res_00000000-0000-4000-8000-0000000000d5"
_LINE = f"{_OBLIGATION} requested_item_never_attempted linked {_RESULT}"
_HEAD = "sha256:" + "ab" * 32


def _envelope(*, gaps: tuple[str, ...], body: str) -> dict[str, object]:
    return {
        "conclusion": "insufficient_coverage",
        "frontier": {"sequence": "4", "head_digest": _HEAD},
        "coverage": {"known_gaps": list(gaps)},
        "suppressed_finding_count": "0",
        "document": {"sections": [{"key": "evidence_and_claim_basis", "body": body}]},
    }


def test_the_receipt_summary_reserves_one_pairing_line_per_obligation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = (
        f"The receipt retains 0 claim references and 1 evidence reference. {CLAIM_VERIFICATION_HEADER} "
        f"{_LINE} The agent wrote that every criterion is met."
    )
    gaps = tuple(f"gap_code_{index:02d}" for index in range(40))
    bare = _envelope(gaps=(), body=body)
    monkeypatch.setattr(summaries, "_MAX_SUMMARY_BYTES", 10_000)
    reserved = summary_for_receipt(bare)
    assert CLAIM_VERIFICATION_HEADER in reserved
    assert _LINE in reserved
    assert "every criterion is met" not in reserved
    bound = len(reserved.encode("ascii")) + 8
    monkeypatch.setattr(summaries, "_MAX_SUMMARY_BYTES", bound)
    tight = summary_for_receipt(_envelope(gaps=gaps, body=body))
    assert len(tight.encode("ascii")) <= bound
    assert CLAIM_VERIFICATION_HEADER in tight
    assert _LINE in tight
    assert "gap codes:" not in tight
    assert "every criterion is met" not in tight


def test_a_receipt_without_the_pairing_header_does_not_invent_a_line() -> None:
    text = summary_for_receipt(
        _envelope(
            gaps=(),
            body=f"{_OBLIGATION} requested_item_never_attempted no_verification_limit",
        )
    )
    assert CLAIM_VERIFICATION_HEADER not in text
    assert _OBLIGATION not in text
