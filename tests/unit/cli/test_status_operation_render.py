"""A finished check's outcome on ``status view=operation`` (issue #1107, W6).

The CLI and the terminal interface render it through ``render_human_status``; the MCP text names
the verdict, the next action and the bounded ``agent_next`` lead. Both read the same service
model a recovery read returns after a lost or cut check result.
"""

from __future__ import annotations

import json
from typing import Any, cast

from builders.status_wire import compact_status
from finishup.cli.render import render_human_status
from finishup.mcp.summaries import MAX_SUMMARY_BYTES, summary_for_status
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import StatusResultModel, StatusSuccessModel, public_model_to_wire

_LEAD = (
    "Next: supply_missing_input (action_required). Supply each item below once, then check again."
)


def _operation_status(outcome: dict[str, Any] | None) -> tuple[StatusSuccessModel, dict[str, Any]]:
    compact = compact_status()
    wire = cast(dict[str, Any], json.loads(json.dumps(public_model_to_wire(compact.result))))
    wire["view"] = "operation"
    page: dict[str, Any] = {
        "operation_request_id": new_id(IdKind.REQUEST),
        "found": True,
        "state": "complete",
        "operation_kind": "check",
        "outcome": None,
        "subject_frontier": None,
        "result_frontier": None,
        "accepted_events": [],
        "continuation": None,
        "next_cursor": None,
    }
    if outcome is not None:
        page["check_outcome"] = outcome
    wire["page"] = page
    success = StatusResultModel.model_validate(wire).root
    assert type(success) is StatusSuccessModel
    return success, wire


def _outcome() -> dict[str, Any]:
    target = new_id(IdKind.RESULT)
    return {
        "verdict": "insufficient_coverage",
        "agent_next": _LEAD,
        "overall_next": {
            "action": "supply_missing_input",
            "status": "action_required",
            "target_refs": [target],
        },
        "missing_for_assessment": [
            {
                "kind": "verification_output",
                "target_refs": [target],
                "availability": "agent_suppliable",
            }
        ],
        "semantic_status": "succeeded",
        "semantic_reason": "semantic_completed",
        "semantic_conclusion": "insufficient_packet",
        "result_frontier": {"sequence": "7", "head_digest": "sha256:" + "2" * 64},
    }


def test_human_status_shows_the_finished_checks_outcome_and_lead() -> None:
    outcome = _outcome()
    success, _wire = _operation_status(outcome)
    lines = render_human_status(success).splitlines()
    assert "Check outcome: insufficient_coverage" in lines
    assert "Next: " + _LEAD.removeprefix("Next: ") in lines
    target = outcome["missing_for_assessment"][0]["target_refs"][0]
    assert any(line.startswith(f"- verification_output ({target})") for line in lines)


def test_human_status_without_an_outcome_is_unchanged() -> None:
    success, _wire = _operation_status(None)
    assert "Check outcome:" not in render_human_status(success)


def test_mcp_status_text_names_the_outcome_within_the_summary_bound() -> None:
    _success, wire = _operation_status(_outcome())
    text = summary_for_status(wire)
    assert "check outcome: insufficient_coverage; next: supply_missing_input;" in text
    assert _LEAD in text
    assert len(text.encode("utf-8")) <= MAX_SUMMARY_BYTES
    # A hostile lead never reaches the text: the service model would refuse it, and the summary
    # re-gates the shape it reads.
    wire["page"]["check_outcome"]["agent_next"] = "line\nbreak"
    assert "line\nbreak" not in summary_for_status(wire)
