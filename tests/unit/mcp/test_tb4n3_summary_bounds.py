"""tb4n3 RC-2 (#1025): the MCP text summaries are composed within their bound and never raise.

Provenance. `scratch_RC/test_n3_1_check_summary_bound.py` and `scratch_A_bounds/tests/test_a_bounds.py`
(families A1, A2, A3, A4) reproduced, on build 26e9cecf, the closing `check` of 10 of 13
deterministic tb4n3 runs overflowing the 512-byte text, `_bounded` raising and the bridge returning
INTERNAL_ERROR `response_projection_failed` with "retry the same request_id". The 512 asserts there
now assert the 4096 contract, and every builder also runs at a 512-byte bound to prove the
composer never raises and keeps the required core (verdict, next instruction, frontier and head
digest) when room is scarce.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from yoetz.mcp import summaries
from yoetz.mcp.summaries import (
    MAX_SUMMARY_BYTES,
    render_safe_compact_summary,
    render_safe_compact_summary_detailed,
    summary_for_check,
    summary_for_public_error,
)

HEAD = "sha256:" + "8" * 64

FINAL_ENDPOINT: dict[str, Any] = {
    "action": "request_receipt",
    "status": "ready_with_limitations",
    "acknowledged_incomplete_endpoint": "receipt",
    "target_refs": [],
}


def _check(**extra: Any) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        "verdict": "insufficient_coverage",
        "findings": [],
        "suppressed_count": "0",
        "semantic_status": "not_requested",
        "semantic_reason": "deterministic_mode",
        "result_frontier": {"sequence": "351", "head_digest": HEAD},
        "coverage": {"known_gaps": []},
    }
    envelope.update(extra)
    return envelope


def _assert_core(text: str, *, verdict: str = "insufficient_coverage") -> None:
    assert text.isascii()
    assert verdict in text
    assert "frontier: 351; head_digest: " + HEAD in text
    assert "overall next: request_receipt; status: ready_with_limitations" in text


@pytest.mark.parametrize(
    ("route_required_false", "awaited", "final"),
    [
        (True, True, True),  # vpp D / music D / cargo D final check: raised on 26e9cecf
        (True, False, True),  # cad D final: 502 bytes, 10 bytes of headroom
        (False, True, True),  # pre-tb4n2 shape (route field omitted)
    ],
)
def test_the_deterministic_closing_check_keeps_its_verdict_and_next_step(
    route_required_false: bool, awaited: bool, final: bool
) -> None:
    envelope = _check(overall_next=FINAL_ENDPOINT if final else None)
    if route_required_false:
        envelope["semantic_route_required"] = False
    if awaited:
        envelope["observations_awaited"] = {"state": "complete", "pending_count": "0"}
    text = summary_for_check(envelope)
    assert len(text) <= MAX_SUMMARY_BYTES
    _assert_core(text)
    assert ("route did not require AI-powered review" in text) == route_required_false
    assert ("hook observations awaited: complete" in text) == awaited


def test_a_failed_review_with_a_timeout_note_and_a_final_endpoint_keeps_the_core() -> None:
    text = summary_for_check(
        _check(
            semantic_status="failed",
            semantic_reason="response_content_invalid",
            observations_awaited={"state": "bounded_timeout", "pending_count": "12"},
            advisory_notes=[{}],
            overall_next=FINAL_ENDPOINT,
        )
    )
    assert len(text) <= MAX_SUMMARY_BYTES
    _assert_core(text)
    assert "bounded_timeout, 12 still pending" in text
    assert "project advice (non-verdict): 1" in text


def test_the_round_stopped_lead_and_a_final_endpoint_fit_and_name_the_stop() -> None:
    """A2: ~250 bytes of lead plus any final clause overflowed every closing check once stopped."""

    text = summary_for_check(
        _check(
            semantic_reason="semantic_insufficient_packet",
            coverage={"known_gaps": ["semantic_review_skipped_insufficient_packet"]},
            overall_next=FINAL_ENDPOINT,
            observations_awaited={"state": "complete"},
            semantic_route_required=False,
        )
    )
    assert len(text) <= MAX_SUMMARY_BYTES
    _assert_core(text)
    assert "AI-powered review skipped" in text
    assert "verify it yourself" in text


def test_public_error_keeps_its_location_beside_the_outcome_hint() -> None:
    """A3: an outcome pointer plus other rejected locations collapsed the text to bare identity."""

    text = summary_for_public_error(
        {
            "ok": False,
            "error": {
                "code": "INVALID_REQUEST",
                "retryable": False,
                "correlation_id": f"err_{uuid.uuid4()}",
                "safe_details": {
                    "fields": [
                        "/event_drafts/12/payload/outcome",
                        "/event_drafts/13/payload/obligation_refs/0",
                        "/event_drafts/14/payload/summary",
                    ],
                    "reasons": ["invalid_type_or_value"] * 3,
                },
            },
        }
    )
    assert "Rejected:" in text and "/event_drafts/12/payload/outcome" in text
    assert "Outcomes: success|failure|partial|unknown" in text
    assert len(text) <= MAX_SUMMARY_BYTES


def test_rendering_is_deterministic_so_a_replay_cannot_fail_where_the_first_call_did() -> None:
    """A4: the stored result is re-rendered on replay; the same input must give the same text."""

    envelope = _check(
        semantic_route_required=False,
        observations_awaited={"state": "complete"},
        overall_next=FINAL_ENDPOINT,
    )
    first = render_safe_compact_summary(envelope)
    assert render_safe_compact_summary(envelope) == first
    assert render_safe_compact_summary_detailed(envelope).failures == ()


def test_a_clause_that_fails_to_render_is_omitted_named_and_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def explode(*_args: object) -> tuple[str, ...]:
        raise RuntimeError("route-clause-defect")

    monkeypatch.setattr(summaries, "_route_variants", explode)
    envelope = _check(semantic_route_required=False, overall_next=FINAL_ENDPOINT)
    rendered = render_safe_compact_summary_detailed(envelope)
    _assert_core(rendered.text)
    assert "summary_render_failed:check.route" in rendered.text
    assert [site for site, _ in rendered.failures] == ["check.route"]


def test_a_builder_whose_core_fails_falls_back_to_verdict_frontier_and_status_pointer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def explode(_envelope: object) -> str:
        raise RuntimeError("check-builder-defect")

    monkeypatch.setattr(summaries, "summary_for_check", explode)
    rendered = render_safe_compact_summary_detailed(
        _check(verdict="action_required", overall_next=FINAL_ENDPOINT)
    )
    assert rendered.text.isascii()
    assert "Check verdict: action_required" in rendered.text
    assert "frontier: 351; head_digest: " + HEAD in rendered.text
    assert "summary_render_failed:check" in rendered.text
    assert "read status view=compact" in rendered.text
    assert [site for site, _ in rendered.failures] == ["check"]


def test_a_non_ascii_value_never_raises_unicode_encode_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A future non-ASCII sentence used to raise UnicodeEncodeError and become the same error."""

    monkeypatch.setattr(summaries, "SEMANTIC_REDACTED_VALUES_AGENT_LINE", "café — line")
    text = summary_for_check(
        _check(
            overall_next=FINAL_ENDPOINT,
            semantic_redacted_values=[
                {"item_id": "item-1", "disposition": "value_replaced", "lines": [3]}
            ],
        )
    )
    assert text.isascii()
    _assert_core(text)


@pytest.fixture
def tight_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(summaries, "_MAX_SUMMARY_BYTES", 512)


def test_every_builder_never_raises_and_keeps_its_core_at_a_512_byte_bound(
    tight_bound: None,
) -> None:
    refs = [f"fnd_00000000-0000-4000-8000-{index:012d}" for index in range(64)]
    check = _check(
        findings=[{"finding_id": ref} for ref in refs[:30]],
        overall_next={
            "action": "work_open_findings",
            "status": "action_required",
            "target_refs": refs,
        },
        observations_awaited={"state": "bounded_timeout", "pending_count": "123"},
        semantic_route_required=False,
        advisory_notes=[{}] * 7,
        children={"label": "recorded", "items": [{}] * 40},
        coverage={"known_gaps": ["semantic_review_skipped_insufficient_packet"] + ["gap_x"] * 60},
    )
    text = summary_for_check(check)
    assert len(text) <= 512
    assert text.isascii()
    assert "overall next: work_open_findings; status: action_required" in text
    assert "frontier: 351; head_digest: " + HEAD in text
    assert "AI-powered review status/reason: not_requested/deterministic_mode" in text

    status_envelope: dict[str, Any] = {
        "view": "compact",
        "head_frontier": {"sequence": "9", "head_digest": HEAD},
        "closure_readiness": {
            "state": "action_required",
            "open_obligation_count": "3",
            "unanswered_finding_count": "2",
            "receipt_blocking_finding_count": "2",
            "acknowledged_not_done_count": "1",
            "agent_actionable": ["obligations_open", "receipt_findings_unresolved"],
            "standing_limitations": [],
        },
        "gaps": ["g"] * 50,
        "page": {"items": [{"freshness": "current", "open_obligations": []}]},
    }
    status = render_safe_compact_summary(status_envelope)
    assert len(status) <= 512 and status.isascii()
    assert "Status view: compact; frontier: 9; head_digest: " + HEAD in status
    assert "open obligations: 3" in status and "Closure: action_required" in status

    receipt_envelope: dict[str, Any] = {
        "receipt_id": "rcp_00000000-0000-4000-8000-000000000001",
        "conclusion": "insufficient_coverage",
        "frontier": {"sequence": "5", "head_digest": HEAD},
        "coverage": {"known_gaps": [f"gap_{index}" for index in range(64)]},
        "suppressed_finding_count": "0",
        "obligations": [
            {"obligation_id": f"obl_00000000-0000-4000-8000-{i:012d}", "status": "open"}
            for i in range(60)
        ],
    }
    receipt = render_safe_compact_summary(receipt_envelope)
    assert len(receipt) <= 512 and receipt.isascii()
    assert "Receipt conclusion: insufficient_coverage" in receipt
    assert "frontier: 5; head_digest: " + HEAD in receipt
    assert "coverage limitations: 64" in receipt


def test_the_recovery_directive_outranks_descriptive_clauses_at_a_tight_bound(
    tight_bound: None,
) -> None:
    """A timed-out review's continuation is the first optional clause granted: it must not lose to
    finding targets or the to-do counts that precede it in reading order."""

    refs = [f"fnd_00000000-0000-4000-8000-{index:012d}" for index in range(1, 4)]
    text = summary_for_check(
        _check(
            semantic_status="timeout",
            semantic_reason="provider_timeout",
            overall_next={
                "action": "work_open_findings",
                "status": "action_required",
                "target_refs": refs,
            },
            finding_checklist={
                "attempt_budget": "5",
                "counts": {
                    "open": "3",
                    "open_at_budget": "0",
                    "verified_resolved": "0",
                    "acknowledged_not_done": "0",
                    "rejection_accepted": "0",
                },
                "next": "work_open_findings",
            },
        )
    )
    assert len(text) <= 512
    assert "Continuation: semantic_timeout." in text


def test_a_failed_success_builder_keeps_the_start_identities_the_next_request_needs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def explode(_source: object) -> str:
        raise RuntimeError("other-success-defect")

    monkeypatch.setattr(summaries, "_summary_for_other_success", explode)
    ids = {
        "task_id": "tsk_00000000-0000-4000-8000-000000000001",
        "session_id": "ses_00000000-0000-4000-8000-000000000002",
        "writer_id": "wri_00000000-0000-4000-8000-000000000003",
    }
    rendered = render_safe_compact_summary_detailed(
        {"outcome": "created", **ids, "result_frontier": {"sequence": "1", "head_digest": HEAD}}
    )
    for value in ids.values():
        assert value in rendered.text
    assert "frontier: 1; head_digest: " + HEAD in rendered.text
    assert "summary_render_failed:operation" in rendered.text


def test_a_long_standing_limitation_list_is_capped_and_never_displaces_a_required_ref() -> None:
    standing = [f"standing_limitation_{index:02d}" for index in range(64)]
    readiness = {
        "state": "ready_with_limitations",
        "open_obligation_count": "0",
        "unanswered_finding_count": "0",
        "receipt_blocking_finding_count": "0",
        "acknowledged_obligation_count": "0",
        "acknowledged_not_done_count": "0",
        "agent_actionable": [],
        "standing_limitations": standing,
        "limitation_refs_required_count": "1",
        "limitation_refs_required": ["res_00000000-0000-4000-8000-000000000001"],
    }
    envelope: dict[str, Any] = {
        "view": "compact",
        "head_frontier": {"sequence": "9", "head_digest": HEAD},
        "closure_readiness": readiness,
        "gaps": [],
        "page": {"items": [{"freshness": "current", "open_obligations": []}]},
    }
    roomy = render_safe_compact_summary(envelope)
    listed = roomy.split("Standing limitations: ", 1)[1]
    assert len(listed) <= 1_100  # the list bound plus its closing sentence
    assert "res_00000000-0000-4000-8000-000000000001" in roomy
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(summaries, "_MAX_SUMMARY_BYTES", 512)
        tight = render_safe_compact_summary(envelope)
    assert len(tight) <= 512
    assert "res_00000000-0000-4000-8000-000000000001" in tight
    assert "Closure: ready_with_limitations" in tight
