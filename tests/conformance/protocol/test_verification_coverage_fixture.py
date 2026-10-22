"""Coverage status keeps advisor labels, text categories and bounded wire shape."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

import pytest

from finishup.cli.render import render_human_status
from finishup.domain.values import freeze_json
from finishup.domain.verification_coverage import verification_coverage_wire_lines
from finishup.protocol.models import (
    DataCategory,
    StatusCoveragePageModel,
    StatusResultModel,
    StatusSuccessModel,
    classify_result_leaf,
    public_model_to_wire,
)
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance
from fixture_loader import load_fixture_json

_PATH = "canonical/verification-coverage-1.4.0.case.json"


def test_golden_coverage_page_roundtrips_and_renders_same_witnesses() -> None:
    fixture = cast(dict[str, Any], load_fixture_json(_PATH))
    wire = fixture["input"]["status_result"]
    validate_schema_instance("status-result", "1.4.0", freeze_json(wire))
    parsed = StatusResultModel.model_validate(wire)
    assert isinstance(parsed.root, StatusSuccessModel)
    assert isinstance(parsed.root.page, StatusCoveragePageModel)
    assert public_model_to_wire(parsed) == wire
    declared = cast(Mapping[str, object], wire["page"]["verification_coverage"])
    lines = verification_coverage_wire_lines(declared)
    assert list(lines) == fixture["expected"]["coverage_lines"]
    assert all(line in render_human_status(parsed.root) for line in lines)


@pytest.mark.parametrize(
    ("suffix", "category"),
    [
        ("task_criterion_quote", DataCategory.TASK_DESCRIPTION),
        ("obligation_criterion_quote", DataCategory.OBLIGATION_TEXT),
        ("witnesses/0/worst", DataCategory.COMMAND_METADATA),
        ("witnesses/0/cases", "public_structural"),
    ],
)
def test_quotes_and_metrics_keep_their_existing_privacy_categories(
    suffix: str, category: object
) -> None:
    fixture = cast(dict[str, Any], load_fixture_json(_PATH))
    wire = fixture["input"]["status_result"]
    index = 1 if suffix == "obligation_criterion_quote" else 0
    assert (
        classify_result_leaf(
            "status", wire, f"/page/verification_coverage/criteria/{index}/{suffix}"
        )
        == category
    )
    receipt_wire = {"ok": True, "format": "json", "document": wire["page"]}
    assert (
        classify_result_leaf(
            "receipt", receipt_wire, f"/document/verification_coverage/criteria/{index}/{suffix}"
        )
        == category
    )


@pytest.mark.parametrize(
    ("key", "value"), [("advisory", False), ("label", "covered"), ("extra", True)]
)
def test_coverage_schema_cannot_become_a_correctness_certificate(key: str, value: object) -> None:
    fixture = cast(dict[str, Any], load_fixture_json(_PATH))
    wire = fixture["input"]["status_result"]
    wire["page"]["verification_coverage"][key] = value
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("status-result", "1.4.0", freeze_json(wire))
