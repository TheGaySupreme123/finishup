"""Manifest-bound golden vector for evidence read-back and the author filter (issue #914).

Status request 1.2.0 and status result 1.4.0 are unreleased on the 0.3 line, so the evidence
``author`` selector and the row ``publication_channel`` were added to them in place; the channel is
optional so rows written by earlier 0.3 builds still validate.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any, cast

import pytest

from finishup.cli.render import render_human_status
from finishup.domain.values import freeze_json
from finishup.mcp.summaries import render_safe_compact_summary
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import (
    StatusEvidencePageModel,
    StatusRequestModel,
    StatusResultModel,
    StatusSuccessModel,
    public_model_to_wire,
)
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance
from fixture_loader import load_fixture_json

_PATH = "canonical/status-evidence-author-1.4.0.case.json"
_CASES = ("mine", "unfiltered")
_GENERATOR = Path(__file__).resolve().parents[3] / "scripts" / "generate_status_evidence_fixture.py"


def _document() -> dict[str, Any]:
    return cast(dict[str, Any], load_fixture_json(_PATH))


def test_vector_is_owned_by_its_generator() -> None:
    spec = importlib.util.spec_from_file_location("_status_evidence_fixture", _GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.build_fixture() == _document()


@pytest.mark.parametrize("case", _CASES)
def test_vector_validates_and_every_rendering_matches(case: str) -> None:
    document = _document()
    request = cast(dict[str, Any], document["input"]["requests"][case])
    result = cast(dict[str, Any], document["input"]["results"][case])
    expected = cast(dict[str, Any], document["expected"])

    validate_schema_instance("status-request", "1.2.0", freeze_json(request))
    StatusRequestModel.model_validate(request)
    validate_schema_instance("status-result", "1.4.0", freeze_json(result))
    wrapped = StatusResultModel.model_validate(result)
    assert public_model_to_wire(wrapped) == result
    success = wrapped.root
    assert isinstance(success, StatusSuccessModel)
    assert isinstance(success.page, StatusEvidencePageModel)
    assert render_human_status(success).splitlines() == expected["human_lines"][case]
    assert render_safe_compact_summary(cast(JsonValue, result)) == expected["mcp_summaries"][case]
    rows = {item.evidence_id: item for item in success.page.items}
    for evidence_id in expected["own_evidence_ids"]:
        assert rows[evidence_id].publication_channel == "cooperative_mcp"
        assert isinstance(rows[evidence_id].description, str)


def test_rows_from_earlier_03_builds_still_validate_without_a_channel() -> None:
    result = cast(dict[str, Any], _document()["input"]["results"]["unfiltered"])
    items = [
        {key: value for key, value in item.items() if key != "publication_channel"}
        for item in result["page"]["items"]
    ]
    earlier = {**result, "page": {**result["page"], "items": items}}
    validate_schema_instance("status-result", "1.4.0", freeze_json(earlier))
    wrapped = StatusResultModel.model_validate(earlier)
    success = wrapped.root
    assert isinstance(success, StatusSuccessModel)
    assert isinstance(success.page, StatusEvidencePageModel)
    assert all(item.publication_channel is None for item in success.page.items)
    assert public_model_to_wire(wrapped) == earlier

    # Renderers omit the missing channel instead of printing a placeholder value.
    expected_lines = [
        line.replace(" cooperative_mcp ", " ").replace(" hook_observed ", " ")
        for line in _document()["expected"]["human_lines"]["unfiltered"]
    ]
    rendered = render_human_status(success).splitlines()
    assert rendered == expected_lines
    assert not any("None" in line for line in rendered)
    summary = render_safe_compact_summary(cast(JsonValue, earlier))
    assert "evidence rows: 3 (unrecorded 3);" in summary
    assert "None" not in summary


@pytest.mark.parametrize("author", ("theirs", "", "MINE"))
def test_author_admits_only_mine(author: str) -> None:
    request = {**_document()["input"]["requests"]["mine"], "filter": {"author": author}}
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("status-request", "1.2.0", freeze_json(request))


@pytest.mark.parametrize("channel", ("caller_asserted", None, ""))
def test_a_present_channel_must_be_closed(channel: object) -> None:
    result = cast(dict[str, Any], _document()["input"]["results"]["unfiltered"])
    items = [dict(item) for item in result["page"]["items"]]
    items[0]["publication_channel"] = channel
    unknown = {**result, "page": {**result["page"], "items": items}}
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("status-result", "1.4.0", freeze_json(unknown))
