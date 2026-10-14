"""tb4n3 RC-2 cross-surface agreement: the check JSON, its MCP text and the CLI say one verdict.

The closing check of 10 of 13 deterministic tb4n3 runs returned no verdict at all on the MCP text
channel, so agents inferred one from status counters and two claimed completion without ever
reading it. This asserts, for every verdict the check can carry and for the verdict-bearing
fields of the receipt and status, that every surface an agent can read names the same answer.
"""

from __future__ import annotations

import json
from typing import Any, cast

import pytest
from tests.unit.protocol.test_models_and_schemas import (
    _check_result_wire,  # pyright: ignore[reportPrivateUsage]
)

from finishup.cli.render import render_human_check
from finishup.domain.findings import CheckVerdict
from finishup.mcp.server import _result_text  # pyright: ignore[reportPrivateUsage]
from finishup.mcp.summaries import MAX_SUMMARY_BYTES
from finishup.protocol.models import CheckResult, CheckSuccessModel, public_model_to_wire

_CLOSING_OVERALL: dict[str, Any] = {
    "action": "request_receipt",
    "status": "ready_with_limitations",
    "acknowledged_incomplete_endpoint": "receipt",
    "target_refs": [],
}


def _wire(verdict: str, **extra: Any) -> dict[str, Any]:
    wire = cast(dict[str, Any], json.loads(json.dumps(_check_result_wire())))
    wire["verdict"] = verdict
    wire.update(extra)
    return wire


def _agreed(verdict: str, **extra: Any) -> tuple[dict[str, Any], str, str]:
    wire = _wire(verdict, **extra)
    result = CheckResult.model_validate(wire).root
    assert type(result) is CheckSuccessModel
    json_wire = public_model_to_wire(CheckResult.model_validate(wire))
    return json_wire, _result_text(json_wire, host_profile="codex"), render_human_check(result)


@pytest.mark.parametrize("verdict", [item.value for item in CheckVerdict])
def test_the_json_verdict_is_the_verdict_in_the_mcp_text_and_the_cli(verdict: str) -> None:
    for status, reason in (("not_requested", "deterministic_mode"),):
        json_wire, text, cli = _agreed(
            verdict,
            semantic_status=status,
            semantic_reason=reason,
            overall_next=_CLOSING_OVERALL,
            semantic_route_required=False,
        )
        assert json_wire["verdict"] == verdict
        scoped_local = (
            verdict == "no_issue_detected"
            and status == "not_requested"
            and reason == "deterministic_mode"
        )
        if scoped_local:
            # Coverage-bounded wording is the same sentence on both text surfaces.
            assert "No issue detected within deterministic coverage" in text
            assert "no issue detected within deterministic coverage" in cli
        else:
            assert verdict in text, text
            assert f"Verdict: {verdict}" in cli
        frontier = json_wire["result_frontier"]
        assert f"frontier: {frontier['sequence']}; head_digest: {frontier['head_digest']}" in text
        assert "overall next: request_receipt; status: ready_with_limitations" in text
        assert f"AI-powered review status/reason: {status}/{reason}" in text
        assert len(text.split("\n")[0]) <= MAX_SUMMARY_BYTES


def test_the_findings_counted_in_the_json_are_the_findings_named_in_the_text() -> None:
    wire = _wire("action_required")
    json_wire, text, _ = _agreed(
        "action_required",
        findings=wire["findings"],
        overall_next={
            "action": "work_open_findings",
            "status": "action_required",
            "target_refs": [row["finding_id"] for row in wire["findings"]],
        },
    )
    for row in json_wire["findings"]:
        assert row["finding_id"] in text
    assert f"findings returned: {len(json_wire['findings'])}" in text
