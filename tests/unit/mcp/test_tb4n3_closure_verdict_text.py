"""N3-6 (tb4n3, issue #1026): a status text never says "done" beside an unexplained blocker.

Moved from ``verify_n3/scratch_RC/test_n3_6_ack_finding_disagreement.py``. On the base 26e9cecf the
MCP status text read "... receipt-blocking findings: 1 ... Nothing further to do. Request the
receipt." for an acknowledged ``acknowledged_not_done`` finding, and the receipt then read
``unresolved_findings_remain``. The phrase is gone from every human surface; the closure state
keeps its owner-approved stop sentence byte for byte, and the predicted receipt conclusion and the
counters that explain it follow it.
"""

from __future__ import annotations

from finishup.mcp.summaries import summary_for_status

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


_FINDING = "fnd_28afe22a-9741-4830-b4eb-84af6faf0262"
# The ``acceptance`` entries are what an earlier 0.3 service sent (ADR-033 D1 retired them).
_RECHECKS = [
    {
        "kind": "acceptance",
        "key": "accept:1a2b3c4d",
        "subjects": ["obl_00000000-0000-4000-8000-000000000001"],
        "rule": "resolved_obligations_acceptance_reread",
        "since_frontier": "5",
    },
    {
        "kind": "acknowledgement",
        "key": "ack:obl_00000000-0000-4000-8000-000000000002",
        "subjects": ["obl_00000000-0000-4000-8000-000000000002"],
        "rule": "obligation_acknowledged_not_done",
        "since_frontier": "6",
    },
]
_FLAGGED = [
    {
        "kind": "acceptance",
        "key": "accept:1a2b3c4d",
        "subjects": ["obl_00000000-0000-4000-8000-000000000001"],
        "rule": "resolved_obligations_acceptance_risk",
        "since_frontier": "5",
    }
]


def _prepared(**readiness: object) -> dict[str, object]:
    status = _status(**readiness)
    return {
        "preparatory_only": True,
        "frontier": status["head_frontier"],
        "closure_readiness": status["closure_readiness"],
        "inventory": {},
        "request": None,
        "notes": [],
    }


_RISKY = "obl_00000000-0000-4000-8000-0000000000c4"
_RISK_ROWS = [{"obligation_id": _RISKY, "reasons": ["evidence_self_asserted_only"]}]
_NOTE_HEAD = "Acceptance provenance"


def _readiness_model(**fields: object) -> object:
    from finishup.protocol.models import StatusClosureReadinessModel

    return StatusClosureReadinessModel.model_validate(
        {
            "declared_obligation_count": "1",
            "no_obligations_reason": None,
            "open_obligation_count": "0",
            "unanswered_finding_count": "0",
            "receipt_blocking_finding_count": "0",
            "blocking_conditions": [],
            "state": "ready_with_limitations",
            "gap_classification_version": "8",
            "agent_actionable": [],
            "standing_limitations": ["unresolved_verification_limitation"],
            "acknowledged_not_done": [],
            "acknowledged_not_done_count": "0",
            **fields,
        }
    )


def test_acceptance_risk_note_once_and_host_independent() -> None:
    """ADR-033 D1: the MCP, CLI, TUI and closure_prepare texts say the provenance limit once.

    The sentence is the same on every host, names the flagged id and its reason, says the Stop
    is not blocked, and never names the retired ``finishup-acceptance`` line or a Stop re-read.
    """

    from typing import cast

    from finishup.cli.render import render_closure_readiness_lines
    from finishup.mcp.summaries import render_safe_compact_summary_detailed
    from finishup.protocol.models import StatusClosureReadinessModel
    from finishup.protocol.readiness_text import acceptance_risk_note

    readiness = {
        "standing_limitations": ["unresolved_verification_limitation"],
        "acceptance_risk": _RISK_ROWS,
        "rechecks": _RECHECKS,  # an older service's acceptance entry beside a real one
    }
    note = acceptance_risk_note(readiness)
    assert note.startswith(_NOTE_HEAD + " (a receipt coverage limit, not a Stop item)")
    assert f"{_RISKY} (evidence_self_asserted_only)" in note
    assert "Stopping is not blocked" in note and "acknowledged_not_done" in note
    for wire in (_status(**readiness), _prepared(**readiness)):
        texts = {
            host: render_safe_compact_summary_detailed(wire, host=host).text
            for host in (None, "codex", "claude", "cursor", "generic")
        }
        assert len(set(texts.values())) == 1, texts
        text = texts[None]
        assert text.count(_NOTE_HEAD) == 1
        assert note in text
        assert "finishup-acceptance" not in text
        assert "At Stop you will be asked once to re-read: the acceptance" not in text
        assert "acceptance criteria" not in text
    model = cast(StatusClosureReadinessModel, _readiness_model(acceptance_risk=_RISK_ROWS))
    lines = render_closure_readiness_lines(model)
    assert sum(line.count(_NOTE_HEAD) for line in lines) == 1
    assert note in lines
    # Nothing flagged: no sentence. A malformed row adds nothing.
    assert acceptance_risk_note({"acceptance_risk": [], "standing_limitations": []}) == ""
    assert acceptance_risk_note({"acceptance_risk": [{"obligation_id": "hello"}]}) == ""
    assert (
        acceptance_risk_note(
            {"acceptance_risk": [{"obligation_id": _RISKY, "reasons": ["it_passed"]}]}
        )
        == ""
    )


def test_acceptance_risk_note_bounds_the_named_ids() -> None:
    from finishup.protocol.readiness_text import acceptance_risk_note

    rows = [
        {
            "obligation_id": f"obl_00000000-0000-4000-8000-{index:012x}",
            "reasons": ["requested_item_never_attempted", "evidence_self_asserted_only"],
        }
        for index in range(1, 11)
    ]
    note = acceptance_risk_note({"acceptance_risk": rows})
    assert note.count("obl_") == 8
    assert "; and 2 more" in note
    short = acceptance_risk_note({"acceptance_risk": rows}, short=True)
    assert "10 obligation(s)" in short and "obl_" not in short


def test_older_service_acceptance_recheck_is_not_announced() -> None:
    """An earlier 0.3 service still sends an ``acceptance`` re-check and no ``acceptance_risk``.

    No surface announces the acceptance re-read; the standing code still yields the fixed receipt
    sentence once, without ids.
    """

    from finishup.domain.receipts import UNRESOLVED_VERIFICATION_LIMITATION
    from finishup.protocol.readiness_text import acceptance_risk_note, recheck_note

    older = [_FLAGGED[0]]
    readiness = {
        "standing_limitations": ["unresolved_verification_limitation"],
        "rechecks": older,
    }
    assert recheck_note(readiness) is None
    for host in ("codex", "claude", "cursor", "generic"):
        assert recheck_note(readiness, host=host) is None
    assert acceptance_risk_note(readiness) == UNRESOLVED_VERIFICATION_LIMITATION
    text = summary_for_status(_status(**readiness))
    assert text.count(_NOTE_HEAD) == 1
    assert "At Stop you will be asked once to re-read" not in text
    assert "finishup-acceptance" not in text
    # Without the standing code there is nothing to fall back to.
    assert acceptance_risk_note({"rechecks": older, "standing_limitations": []}) == ""


def test_the_announced_rechecks_follow_the_stop_sentence_on_every_surface() -> None:
    """A "nothing further to do" is never followed by a surprise gate: the text names the re-reads."""

    from finishup.domain.closure import recheck_note
    from finishup.protocol.readiness_text import recheck_note as shared

    readiness = _status(rechecks=_RECHECKS)["closure_readiness"]
    sentence = shared(readiness)
    assert sentence is not None
    # ADR-033 D1: an ``acceptance`` entry is never announced; the acknowledgement re-check is.
    assert "acceptance" not in sentence
    assert "obligations you recorded as not done" in sentence
    assert recheck_note is shared  # closure_prepare, status text, CLI and TUI say the same thing
    text = summary_for_status(_status(rechecks=_RECHECKS))
    assert _STOP in text
    assert "At Stop you will be asked once to re-read" in text
    assert text.index(_STOP) < text.index("At Stop you will be asked once to re-read")
    assert shared({"rechecks": []}) is None
    assert shared({}) is None  # an earlier build sent no list: nothing is announced


def test_findings_awaiting_a_ruling_are_named_with_the_frontier_of_the_rejection() -> None:
    from finishup.protocol.readiness_text import awaiting_ruling_variants

    counts: dict[str, str] = {
        "to_do": "1",
        "awaiting_ruling": "1",
        "unmet": "0",
        "disclosed": "0",
        "to_disclose": "0",
        "self_verify_eligible": "0",
    }
    readiness: dict[str, object] = {
        "finding_counts": counts,
        "awaiting_ruling_findings": [{"finding_id": _FINDING, "since_frontier": "412"}],
    }
    variants = awaiting_ruling_variants(readiness)
    assert variants[0] == (
        f"1 finding(s) you rejected await a reviewer ruling: {_FINDING} (rejected at frontier 412)."
    )
    assert variants[-1].endswith(".") and len(variants[-1]) < len(variants[0])
    # Nothing awaits a ruling, or an older service named no findings: no guess, no sentence.
    assert awaiting_ruling_variants({"finding_counts": {**counts, "awaiting_ruling": "0"}}) == ()
    assert awaiting_ruling_variants({}) == ()
    # A count without ids still says that something waits, and where to see it.
    bare = awaiting_ruling_variants({"finding_counts": counts})
    assert bare and "status view=findings lists them" in bare[0]
