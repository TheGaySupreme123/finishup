"""Manifest-bound golden vector for a finished check's operation page (issue #1107, W6)."""

from __future__ import annotations

from typing import Any, cast

import pytest

from finishup.cli.render import render_human_status
from finishup.domain.review_input_render import render_agent_next
from finishup.domain.values import freeze_json
from finishup.mcp.summaries import render_safe_compact_summary
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.protocol.models import (
    StatusOperationPageModel,
    StatusResultModel,
    StatusSuccessModel,
    public_model_to_wire,
)
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance
from fixture_loader import load_fixture_json

_PATH = "canonical/status-check-outcome-1.4.0.case.json"


def _document() -> dict[str, Any]:
    return cast(dict[str, Any], load_fixture_json(_PATH))


def test_outcome_vector_validates_and_every_rendering_matches() -> None:
    document = _document()
    result = cast(dict[str, Any], document["input"]["result"])
    expected = cast(dict[str, Any], document["expected"])

    validate_schema_instance("status-result", "1.4.0", freeze_json(result))
    model = StatusResultModel.model_validate(result)
    assert public_model_to_wire(model) == result
    assert canonical_encode(cast(JsonValue, result)).hex() == expected["canonical_hex"]
    assert canonical_digest(cast(JsonValue, result)) == expected["digest"]
    success = model.root
    assert isinstance(success, StatusSuccessModel)
    assert isinstance(success.page, StatusOperationPageModel)
    outcome = success.page.check_outcome
    assert outcome is not None
    assert (success.page.state, success.page.operation_kind) == ("complete", "check")
    # The page's lead is the one the check result composes from the same next action and items.
    wire = result["page"]["check_outcome"]
    assert wire["agent_next"] == render_agent_next(
        wire["overall_next"], wire["missing_for_assessment"]
    )
    assert [item["availability"] for item in wire["missing_for_assessment"]] == [
        "agent_suppliable",
        "yoetz_limit_packet_room",
    ]
    lines = render_human_status(success).splitlines()
    start = lines.index(expected["text_lines"][0])
    assert lines[start : start + len(expected["text_lines"])] == expected["text_lines"]
    assert render_safe_compact_summary(cast(JsonValue, result)) == expected["mcp_summary"]


@pytest.mark.parametrize(
    ("state", "kind"), (("pending", "check"), ("complete", "publish_work"), ("absent", None))
)
def test_schema_and_model_confine_the_outcome_to_a_completed_check(
    state: str, kind: str | None
) -> None:
    result = cast(dict[str, Any], _document()["input"]["result"])
    page = {**result["page"], "state": state, "operation_kind": kind}
    if state == "absent":
        page["found"] = False
    mutated = {**result, "page": page}
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("status-result", "1.4.0", freeze_json(mutated))
    with pytest.raises(ValueError):
        StatusResultModel.model_validate(mutated)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("agent_next", "line one\nline two"),
        ("agent_next", "x" * 2_049),
        ("verdict", "passed"),
        ("reviewer_prose", "hidden"),
    ),
)
def test_schema_rejects_an_open_or_malformed_outcome(field: str, value: str) -> None:
    result = cast(dict[str, Any], _document()["input"]["result"])
    outcome = {**result["page"]["check_outcome"], field: value}
    mutated = {**result, "page": {**result["page"], "check_outcome": outcome}}
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("status-result", "1.4.0", freeze_json(mutated))
