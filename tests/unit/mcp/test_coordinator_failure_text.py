"""A coordinator failure stays in the MCP check and receipt summaries at a tight cap."""

from __future__ import annotations

import pytest

from finishup.domain.receipts import COORDINATOR_FAILURE_LIMITATION
from finishup.mcp import summaries
from finishup.mcp.summaries import summary_for_check, summary_for_receipt

_HEAD = "sha256:" + "cd" * 32


def test_the_check_summary_reserves_the_coordinator_failure_sentence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope = {
        "verdict": "insufficient_coverage",
        "semantic_status": "failed",
        "semantic_reason": "coordinator_failure",
        "result_frontier": {"sequence": "3", "head_digest": _HEAD},
        "coverage": {"known_gaps": [f"gap_code_{index:02d}" for index in range(40)]},
    }
    monkeypatch.setattr(summaries, "_MAX_SUMMARY_BYTES", 10_000)
    wide = summary_for_check(
        {
            **envelope,
            "coverage": {"known_gaps": []},
        }
    )
    assert COORDINATOR_FAILURE_LIMITATION in wide
    assert "status/reason:" not in wide
    bound = len(wide.encode("ascii")) + 8
    monkeypatch.setattr(summaries, "_MAX_SUMMARY_BYTES", bound)
    tight = summary_for_check(envelope)
    assert len(tight.encode("ascii")) <= bound
    assert COORDINATOR_FAILURE_LIMITATION in tight
    assert "gap codes:" not in tight or "gap_code_" not in tight


def test_the_receipt_summary_reserves_the_coordinator_failure_sentence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def envelope(*, gaps: tuple[str, ...]) -> dict[str, object]:
        return {
            "conclusion": "insufficient_coverage",
            "frontier": {"sequence": "4", "head_digest": _HEAD},
            "coverage": {"known_gaps": list(gaps)},
            "suppressed_finding_count": "0",
            "document": {
                "sections": [
                    {
                        "key": "limitations_and_coverage",
                        "body": COORDINATOR_FAILURE_LIMITATION,
                    }
                ]
            },
        }

    monkeypatch.setattr(summaries, "_MAX_SUMMARY_BYTES", 10_000)
    wide = summary_for_receipt(envelope(gaps=()))
    assert COORDINATOR_FAILURE_LIMITATION in wide
    bound = len(wide.encode("ascii")) + 8
    monkeypatch.setattr(summaries, "_MAX_SUMMARY_BYTES", bound)
    tight = summary_for_receipt(
        envelope(gaps=tuple(f"gap_code_{index:02d}" for index in range(40)))
    )
    assert len(tight.encode("ascii")) <= bound
    assert COORDINATOR_FAILURE_LIMITATION in tight
    assert "gap codes:" not in tight
