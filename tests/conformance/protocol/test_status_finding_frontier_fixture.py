"""Manifest-bound golden vector for the record frontier on status finding items (issue #917)."""

from __future__ import annotations

from typing import Any, cast

import pytest

from finishup.cli.render import render_human_status
from finishup.domain.values import freeze_json
from finishup.mcp.summaries import render_safe_compact_summary
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import (
    StatusFindingsPageModel,
    StatusResultModel,
    StatusSuccessModel,
    public_model_to_wire,
)
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance
from fixture_loader import load_fixture_json

_PATH = "canonical/status-finding-frontier-1.4.0.case.json"


def _document() -> dict[str, Any]:
    return cast(dict[str, Any], load_fixture_json(_PATH))


def test_finding_frontier_vector_validates_and_every_rendering_matches() -> None:
    document = _document()
    result = cast(dict[str, Any], document["input"]["result"])
    expected = cast(dict[str, Any], document["expected"])

    validate_schema_instance("status-result", "1.4.0", freeze_json(result))
    model = StatusResultModel.model_validate(result)
    assert public_model_to_wire(model) == result
    success = model.root
    assert isinstance(success, StatusSuccessModel)
    assert isinstance(success.page, StatusFindingsPageModel)
    for item in success.page.items:
        # The record frontier follows the state the check tested, never equals it.
        assert item.finding_frontier is not None
        assert int(item.finding_frontier.sequence) > int(item.subject_frontier.sequence)
    lines = [
        line for line in render_human_status(success).splitlines() if "finding_frontier" in line
    ]
    assert lines == expected["text_lines"]
    assert render_safe_compact_summary(cast(JsonValue, result)) == expected["mcp_summary"]


def test_items_without_a_record_frontier_stay_valid() -> None:
    """Older status producers omit the optional field; it is never null."""

    result = cast(dict[str, Any], _document()["input"]["result"])
    items = [
        {key: value for key, value in item.items() if key != "finding_frontier"}
        for item in result["page"]["items"]
    ]
    legacy = {**result, "page": {**result["page"], "items": items}}
    validate_schema_instance("status-result", "1.4.0", freeze_json(legacy))
    assert public_model_to_wire(StatusResultModel.model_validate(legacy)) == legacy
    nulled = {
        **result,
        "page": {**result["page"], "items": [{**items[0], "finding_frontier": None}]},
    }
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("status-result", "1.4.0", freeze_json(nulled))


@pytest.mark.parametrize(
    "frontier",
    (
        {"sequence": "12"},
        {"sequence": "twelve", "head_digest": "sha256:" + "b2" * 32},
        {"sequence": "12", "head_digest": "sha256:" + "b2" * 32, "extra": "x"},
    ),
)
def test_schema_rejects_malformed_record_frontier(frontier: dict[str, str]) -> None:
    result = cast(dict[str, Any], _document()["input"]["result"])
    item = {**result["page"]["items"][0], "finding_frontier": frontier}
    mutated = {**result, "page": {**result["page"], "items": [item]}}
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("status-result", "1.4.0", freeze_json(mutated))
