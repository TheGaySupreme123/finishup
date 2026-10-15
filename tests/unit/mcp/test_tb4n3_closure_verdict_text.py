"""N3-6 (tb4n3, issue #1026): a status text never says "done" beside an unexplained blocker.

Moved from ``verify_n3/scratch_RC/test_n3_6_ack_finding_disagreement.py``. On the base 26e9cecf the
MCP status text read "... receipt-blocking findings: 1 ... Nothing further to do. Request the
receipt." for an acknowledged ``acknowledged_not_done`` finding, and the receipt then read
``unresolved_findings_remain``. The phrase is gone from every human surface; the closure state
keeps its owner-approved stop sentence byte for byte, and the predicted receipt conclusion and the
counters that explain it follow it.
"""

from __future__ import annotations

import pytest

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


def test_the_announced_rechecks_follow_the_stop_sentence_on_every_surface() -> None:
    """A "nothing further to do" is never followed by a surprise gate: the text names the re-reads."""

    from finishup.domain.closure import recheck_note
    from finishup.protocol.readiness_text import recheck_note as shared

    readiness = _status(rechecks=_RECHECKS)["closure_readiness"]
    sentence = shared(readiness)
    assert sentence is not None
    assert "the acceptance criteria of your resolved obligations" in sentence
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


_FLAGGED = [
    {
        "kind": "acceptance",
        "key": "accept:1a2b3c4d",
        "subjects": ["obl_00000000-0000-4000-8000-000000000001"],
        "rule": "resolved_obligations_acceptance_risk",
        "since_frontier": "5",
    }
]
_LINE = "`finishup-acceptance:<obligation id>:met:<evd_ or res_ id>`"


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


def test_the_mcp_summary_names_the_acceptance_line_only_where_the_host_can_deliver_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1050 follow-up: the bridge's host reaches the status and closure_prepare summaries. Cursor
    (no final answer at Stop) gets the Cursor wording, a generic bridge names which hosts read the
    line, and Codex and Claude Code text is byte-identical to the host-less render."""

    from finishup.mcp import server
    from finishup.mcp.summaries import render_safe_compact_summary_detailed

    for wire in (_status(rechecks=_FLAGGED), _prepared(rechecks=_FLAGGED)):
        unhosted = render_safe_compact_summary_detailed(wire).text
        assert _LINE in unhosted
        for host in ("codex", "claude"):
            assert render_safe_compact_summary_detailed(wire, host=host).text == unhosted
            assert server._result_text(wire, host_profile=host) == unhosted  # pyright: ignore[reportPrivateUsage]
        cursor = render_safe_compact_summary_detailed(wire, host="cursor").text
        assert "finishup-acceptance" not in cursor
        assert "Cursor passes FinishUP no final answer" in cursor
        generic = render_safe_compact_summary_detailed(wire, host="generic").text
        assert f"on Codex and Claude Code a line {_LINE}" in generic
        assert "Cursor passes no final answer" in generic
        assert server._result_text(wire, host_profile="generic") == generic  # pyright: ignore[reportPrivateUsage]
        # Cursor's bridge normally sends the canonical JSON copy; its summary fallback (when that
        # encoding fails) carries the Cursor wording too.
        with monkeypatch.context() as patch:

            def refuse(_value: object) -> bytes:
                raise ValueError("encode_failed")

            patch.setattr(server, "canonical_encode", refuse)

            def unrecorded(*_args: object, **_kwargs: object) -> str:
                return ""

            patch.setattr(server, "_record_summary_degradation", unrecorded)
            fallback = server._result_text(wire, host_profile="cursor")  # pyright: ignore[reportPrivateUsage]
        assert "finishup-acceptance" not in fallback
        assert "Cursor passes FinishUP no final answer" in fallback
