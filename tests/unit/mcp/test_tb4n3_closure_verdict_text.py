"""N3-6 (tb4n3, issue #1026): a status text never says "done" beside an unexplained blocker.

Moved from ``verify_n3/scratch_RC/test_n3_6_ack_finding_disagreement.py``. On the base 26e9cecf the
MCP status text read "... receipt-blocking findings: 1 ... Nothing further to do. Request the
receipt." for an acknowledged ``acknowledged_not_done`` finding, and the receipt then read
``unresolved_findings_remain``. The phrase is gone from every human surface; the closure state
keeps its owner-approved stop sentence byte for byte, and the predicted receipt conclusion and the
counters that explain it follow it.
"""

from __future__ import annotations

from yoetz.mcp.summaries import summary_for_status

_HEAD = "sha256:" + "a" * 64
_STOP = (
    "Nothing further to do. 0 standing limitation(s) and 1 acknowledged item(s) will be "
    "disclosed on the receipt. Request the receipt."
)


def _status(**readiness: object) -> dict[str, object]:
    return {
        "view": "compact",
        "head_frontier": {"sequence": "563", "head_digest": _HEAD},
        "gaps": [],
        "closure_readiness": {
            "state": "ready_with_limitations",
            "agent_actionable": [],
            "standing_limitations": [],
            "acknowledged_not_done_count": "1",
            "receipt_blocking_finding_count": "1",
            "open_obligation_count": "0",
            "unanswered_finding_count": "0",
            **readiness,
        },
    }


def test_the_stop_sentence_is_followed_by_the_conclusion_the_receipt_will_carry() -> None:
    text = summary_for_status(
        _status(
            finding_counts={
                "to_do": "0",
                "awaiting_ruling": "0",
                "unmet": "1",
                "disclosed": "0",
                "to_disclose": "0",
                "self_verify_eligible": "0",
            },
            predicted_receipt={
                "conclusion": "unresolved_findings_remain",
                "reasons": [
                    {
                        "code": "findings_unmet",
                        "rule": "R2",
                        "count": "1",
                        "refs": ["fnd_28afe22a-9741-4830-b4eb-84af6faf0262"],
                    }
                ],
                "reason_total": "1",
                "basis_frontier": "563",
                "provisional": False,
            },
        )
    )
    assert _STOP in text  # the owner-approved sentence, unedited
    assert text.index(_STOP) < text.index("The receipt will read unresolved_findings_remain")
    assert "1 acknowledged requirement(s) not met" in text
    assert "unmet (acknowledged requirements): 1" in text
    assert "receipt-blocking" not in text.lower()


def test_a_status_from_a_build_without_the_verdict_never_prints_the_old_phrase() -> None:
    text = summary_for_status(_status())
    assert "Closure: ready_with_limitations." in text
    assert "receipt-blocking" not in text.lower()
    assert "The receipt will read" not in text  # nothing is guessed when nothing was reported
