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

_PATH = "canonical/status-semantic-progress-1.5.0.case.json"
# The released 1.4.0 vector predates the closure-readiness checklist (#913). Released canonical
# vectors are append-only, so it stays byte-frozen and is read back here as a historical wire.
_RELEASED_PATH = "canonical/status-semantic-progress-1.4.0.case.json"
_CHECKLIST_FIELDS = frozenset(
    {
        "acknowledged_not_done",
        "acknowledged_not_done_count",
        "agent_actionable",
        "gap_classification_version",
        "standing_limitations",
        "state",
    }
)
_CASES = ("active", "overdue", "terminal")


def _document(path: str = _PATH) -> dict[str, Any]:
    return cast(dict[str, Any], load_fixture_json(path))


@pytest.mark.parametrize("case", _CASES)
def test_progress_vector_validates_and_every_rendering_matches(case: str) -> None:
    document = _document()
    result = cast(dict[str, Any], document["input"]["results"][case])
    expected = cast(dict[str, Any], document["expected"])

    validate_schema_instance("status-result", "1.5.0", freeze_json(result))
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


@pytest.mark.parametrize("case", _CASES)
def test_released_pre_checklist_vector_still_reads_back(case: str) -> None:
    released = _document(_RELEASED_PATH)
    result = cast(dict[str, Any], released["input"]["results"][case])

    for version in ("1.4.0", "1.5.0"):
        validate_schema_instance("status-result", version, freeze_json(result))
    success = StatusResultModel.model_validate(result).root
    assert public_model_to_wire(StatusResultModel.model_validate(result)) == result
    assert isinstance(success, StatusSuccessModel)
    assert isinstance(success.page, StatusOperationPageModel)
    progress = success.page.semantic_progress
    assert progress is not None
    assert (
        list(render_semantic_progress_lines(progress)) == released["expected"]["text_lines"][case]
    )
    # The current vector is the released page plus only the checklist fields; its MCP summary
    # supersedes the released one, which is not asserted against current rendering.
    current = cast(dict[str, Any], _document()["input"]["results"][case])
    readiness = cast(dict[str, Any], current["closure_readiness"])
    assert set(readiness) - set(result["closure_readiness"]) == _CHECKLIST_FIELDS
    trimmed = {key: readiness[key] for key in readiness if key not in _CHECKLIST_FIELDS}
    assert {**current, "closure_readiness": trimmed} == result


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
        validate_schema_instance("status-result", "1.5.0", freeze_json(mutated))


def test_model_enforces_the_numeric_relation_json_schema_cannot_express() -> None:
    """``active`` means time remains; the public model rejects ``active`` with none left."""

    result = cast(dict[str, Any], _document()["input"]["results"]["overdue"])
    progress = {**result["page"]["semantic_progress"], "condition": "active"}
    mutated = {**result, "page": {**result["page"], "semantic_progress": progress}}
    validate_schema_instance("status-result", "1.5.0", freeze_json(mutated))
    with pytest.raises(ValueError):
        StatusResultModel.model_validate(mutated)
