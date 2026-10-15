"""Manifest-bound golden vector for structural semantic progress (issue #571 item A2)."""

from __future__ import annotations

from typing import Any, cast

import pytest

from finishup.cli.render import render_human_status, render_semantic_progress_lines
from finishup.domain.values import freeze_json
from finishup.mcp.summaries import render_safe_compact_summary
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import (
    StatusOperationPageModel,
    StatusResultModel,
    StatusSuccessModel,
    public_model_to_wire,
)
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance
from fixture_loader import load_fixture_json

_PATH = "canonical/status-semantic-progress-1.4.0.case.json"
_CASES = ("active", "overdue", "terminal")


def _document() -> dict[str, Any]:
    return cast(dict[str, Any], load_fixture_json(_PATH))


@pytest.mark.parametrize("case", _CASES)
def test_progress_vector_validates_and_every_rendering_matches(case: str) -> None:
    document = _document()
    result = cast(dict[str, Any], document["input"]["results"][case])
    expected = cast(dict[str, Any], document["expected"])

    validate_schema_instance("status-result", "1.4.0", freeze_json(result))
    success = StatusResultModel.model_validate(result).root
    assert isinstance(success, StatusSuccessModel)
    # The wire round-trips byte-for-byte through the public model.
    assert public_model_to_wire(StatusResultModel.model_validate(result)) == result
    assert isinstance(success.page, StatusOperationPageModel)
    progress = success.page.semantic_progress
    assert progress is not None
    lines = list(render_semantic_progress_lines(progress))
    assert lines == expected["text_lines"][case]
    assert all(line in render_human_status(success).splitlines() for line in lines)
    assert render_safe_compact_summary(cast(JsonValue, result)) == expected["mcp_summaries"][case]
    assert set(result["page"]["semantic_progress"]) <= set(expected["progress_fields"])


@pytest.mark.parametrize(
    ("case", "field", "value"),
    (
        ("active", "reasoning_text", "hidden"),
        ("active", "phase", "streaming_tokens"),
        ("active", "terminal_outcome", "failed"),
        ("terminal", "remaining_ms", "1"),
        ("overdue", "condition", "terminal"),
    ),
)
def test_schema_rejects_open_or_contradictory_progress(case: str, field: str, value: str) -> None:
    result = cast(dict[str, Any], _document()["input"]["results"][case])
    progress = dict(result["page"]["semantic_progress"])
    progress[field] = value
    mutated = {**result, "page": {**result["page"], "semantic_progress": progress}}
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("status-result", "1.4.0", freeze_json(mutated))


def test_model_enforces_the_numeric_relation_json_schema_cannot_express() -> None:
    """``active`` means time remains; the public model rejects ``active`` with none left."""

    result = cast(dict[str, Any], _document()["input"]["results"]["overdue"])
    progress = {**result["page"]["semantic_progress"], "condition": "active"}
    mutated = {**result, "page": {**result["page"], "semantic_progress": progress}}
    validate_schema_instance("status-result", "1.4.0", freeze_json(mutated))
    with pytest.raises(ValueError):
        StatusResultModel.model_validate(mutated)
