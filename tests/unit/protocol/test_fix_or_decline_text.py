"""Fix or decline before the receipt: the directive, its codes and its reach (issue #1209)."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

from finishup.cli.closure_gate import closure_gate_from_readiness
from finishup.domain.review_input_render import render_agent_next
from finishup.domain.values import obligation_id
from finishup.kernel.closure_readiness import (
    GAP_CLASSIFICATION,
    GAP_CLASSIFICATION_VERSION,
    ClosureReadinessFacts,
    GapClass,
    derive_closure_readiness,
)
from finishup.kernel.task_facts import FIX_OR_DECLINE_TASK_FACT_GAPS
from finishup.protocol.readiness_text import (
    FIX_OR_DECLINE_CODES,
    fix_or_decline_rows,
    fix_or_decline_variants,
    readiness_directive,
)

_A = obligation_id("obl_12090000-0000-4000-8000-000000000001")
_B = obligation_id("obl_12090000-0000-4000-8000-000000000002")
_FROZEN = (
    "Nothing further to do. 2 standing limitation(s) and 0 acknowledged item(s) will be "
    "disclosed on the receipt. Request the receipt."
)


def _facts(**changes: object) -> ClosureReadinessFacts:
    base = ClosureReadinessFacts(
        check_applicability="applicable",
        semantic_review_current=False,
        receipt_blocking_finding_ids=(),
        acknowledged_finding_ids=(),
        acknowledged_obligation_ids=(),
    )
    return replace(base, **changes)  # type: ignore[arg-type]


def test_the_codes_are_the_gap_tables_fix_or_decline_group_and_the_version_moved() -> None:
    group = {code for code, row in GAP_CLASSIFICATION.items() if row is GapClass.FIX_OR_DECLINE}
    assert group == set(FIX_OR_DECLINE_CODES) == FIX_OR_DECLINE_TASK_FACT_GAPS
    assert GAP_CLASSIFICATION_VERSION == "9"


def test_open_items_are_named_but_never_agent_work() -> None:
    split = derive_closure_readiness(
        ("coverage_gaps_declared",),
        ("host_outcome_unavailable", "requested_output_unchanged"),
        _facts(fix_or_decline=(("requested_output_unchanged", _A),)),
        semantic_review_required=False,
    )
    assert split.state == "ready_with_limitations"
    assert split.agent_actionable == ()
    assert split.standing_limitations == ("host_outcome_unavailable", "requested_output_unchanged")
    assert split.fix_or_decline == (("requested_output_unchanged", _A),)


def test_an_item_whose_code_the_receipt_would_not_disclose_is_not_named() -> None:
    split = derive_closure_readiness(
        ("coverage_gaps_declared",),
        ("host_outcome_unavailable",),
        _facts(fix_or_decline=(("planned_verification_agent_linked", _A),)),
        semantic_review_required=False,
    )
    assert split.fix_or_decline == ()


def test_the_directive_names_each_item_and_counts_the_other_limitations() -> None:
    rows = (
        ("planned_verification_agent_linked", _A),
        ("requested_output_unchanged", _A),
        ("requested_output_unchanged", _B),
    )
    text = readiness_directive(
        "ready_with_limitations", standing=3, acknowledged=1, fix_or_decline=rows
    )
    assert text.startswith(
        "Before the receipt: fix, or decline with a reason: "
        f"planned_verification_agent_linked ({_A}), requested_output_unchanged ({_A} or {_B})."
    )
    assert "finishup-assumption:<obligation id>" in text
    assert "1 other limitation(s) and 1 acknowledged item(s) will be disclosed" in text
    assert "Nothing further to do" not in text
    assert text.isascii()


def test_without_an_open_item_the_frozen_sentence_is_unchanged() -> None:
    assert readiness_directive("ready_with_limitations", standing=2) == _FROZEN
    assert readiness_directive("ready_with_limitations", standing=2, fix_or_decline=()) == _FROZEN
    # A row only ever changes the ready_with_limitations sentence.
    rows = (("requested_output_unchanged", _A),)
    assert readiness_directive("ready", fix_or_decline=rows) == (
        "Nothing further to do. Request the receipt."
    )


def test_rows_are_read_from_closed_tokens_only() -> None:
    readiness = {
        "fix_or_decline": [
            {"code": "requested_output_unchanged", "obligation_id": _A},
            {"code": "host_outcome_unavailable", "obligation_id": _A},
            {"code": "requested_output_unchanged", "obligation_id": "not an id"},
            {"code": "requested_output_unchanged", "obligation_id": _A},
        ]
    }
    assert fix_or_decline_rows(readiness) == (("requested_output_unchanged", _A),)
    assert fix_or_decline_rows({}) == ()
    assert fix_or_decline_variants(()) == ()


def test_agent_next_names_the_items_before_the_receipt() -> None:
    overall: dict[str, object] = {
        "action": "request_receipt",
        "status": "ready_with_limitations",
        "target_refs": [],
        "acknowledged_incomplete_endpoint": "receipt",
    }
    rows = (("requested_output_unchanged", _A),)
    text = render_agent_next(overall, fix_or_decline=rows)
    assert text.startswith("Next: request_receipt (ready_with_limitations).")
    assert f"fix, or decline with a reason: requested_output_unchanged ({_A})" in text
    assert render_agent_next(overall) == render_agent_next(overall, fix_or_decline=())
    assert "Before the receipt" not in render_agent_next(overall)


def test_an_open_item_is_never_a_stop_item() -> None:
    readiness = SimpleNamespace(
        state="ready_with_limitations",
        agent_actionable=(),
        standing_limitations=("requested_output_unchanged",),
        fix_or_decline=(SimpleNamespace(code="requested_output_unchanged", obligation_id=_A),),
        open_obligation_count="0",
        receipt_blocking_finding_count="0",
    )
    gate = closure_gate_from_readiness(
        readiness,
        frontier_sequence="7",
        frontier_digest="sha256:" + "d" * 64,
        observation_pending=False,
    )
    assert gate is None
