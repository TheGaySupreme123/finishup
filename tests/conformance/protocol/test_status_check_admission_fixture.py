"""Manifest-bound golden vector for the absent page's pre-admission stage (issue #838)."""

from __future__ import annotations

from typing import Any, cast

import pytest

from finishup.cli.render import render_check_admission_lines, render_human_status
from finishup.domain.values import freeze_json
from finishup.mcp.summaries import render_safe_compact_summary
from finishup.ports.ledger import CheckAdmissionStage
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import (
    StatusCheckAdmissionModel,
    StatusOperationPageModel,
    StatusResultModel,
    StatusSuccessModel,
    public_model_to_wire,
)
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance
from fixture_loader import load_fixture_json

_PATH = "canonical/status-check-admission-1.5.0.case.json"
# The released 1.4.0 vector predates the closure-readiness checklist (#913). Released canonical
# vectors are append-only, so it stays byte-frozen and is read back here as a historical wire.
_RELEASED_PATH = "canonical/status-check-admission-1.4.0.case.json"
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
_CASES = ("capture_refused", "acquiring", "unknown")


def _document(path: str = _PATH) -> dict[str, Any]:
    return cast(dict[str, Any], load_fixture_json(path))


@pytest.mark.parametrize("case", _CASES)
def test_admission_vector_validates_and_every_rendering_matches(case: str) -> None:
    document = _document()
    result = cast(dict[str, Any], document["input"]["results"][case])
    expected = cast(dict[str, Any], document["expected"])

    validate_schema_instance("status-result", "1.5.0", freeze_json(result))
    success = StatusResultModel.model_validate(result).root
    assert isinstance(success, StatusSuccessModel)
    assert public_model_to_wire(StatusResultModel.model_validate(result)) == result
    assert isinstance(success.page, StatusOperationPageModel)
    assert success.page.state == "absent" and success.page.found is False
    admission = success.page.admission
    lines = [] if admission is None else list(render_check_admission_lines(admission))
    assert lines == expected["text_lines"][case]
    assert all(line in render_human_status(success).splitlines() for line in lines)
    assert render_safe_compact_summary(cast(JsonValue, result)) == expected["mcp_summaries"][case]
    if admission is not None:
        assert set(result["page"]["admission"]) == set(expected["admission_fields"])


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
    admission = success.page.admission
    lines = [] if admission is None else list(render_check_admission_lines(admission))
    assert lines == released["expected"]["text_lines"][case]
    # The current vector is the released page plus only the checklist fields; its MCP summary
    # supersedes the released one, which is not asserted against current rendering.
    current = cast(dict[str, Any], _document()["input"]["results"][case])
    readiness = cast(dict[str, Any], current["closure_readiness"])
    assert set(readiness) - set(result["closure_readiness"]) == _CHECKLIST_FIELDS
    trimmed = {key: readiness[key] for key in readiness if key not in _CHECKLIST_FIELDS}
    assert {**current, "closure_readiness": trimmed} == result


def test_wire_stage_vocabulary_matches_the_ledger_port() -> None:
    field = StatusCheckAdmissionModel.model_fields["stage"]
    assert set(cast(Any, field.annotation).__args__) == {
        stage.value for stage in CheckAdmissionStage
    }


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("request_body", "hidden"),
        ("stage", "semantic_wait"),
        ("refusal_count", "-1"),
        ("retry_after_ms", "soon"),
    ),
)
def test_schema_rejects_open_or_malformed_admission(field: str, value: str) -> None:
    result = cast(dict[str, Any], _document()["input"]["results"]["capture_refused"])
    admission = {**result["page"]["admission"], field: value}
    mutated = {**result, "page": {**result["page"], "admission": admission}}
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("status-result", "1.5.0", freeze_json(mutated))


def test_schema_and_model_confine_admission_to_absent_pages() -> None:
    result = cast(dict[str, Any], _document()["input"]["results"]["capture_refused"])
    pending = {
        **result,
        "page": {**result["page"], "found": True, "state": "pending", "operation_kind": "check"},
    }
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("status-result", "1.5.0", freeze_json(pending))
    with pytest.raises(ValueError):
        StatusResultModel.model_validate(pending)


def test_zero_refusals_is_only_valid_while_acquiring() -> None:
    result = cast(dict[str, Any], _document()["input"]["results"]["capture_refused"])
    admission = {**result["page"]["admission"], "refusal_count": "0"}
    mutated = {**result, "page": {**result["page"], "admission": admission}}
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("status-result", "1.5.0", freeze_json(mutated))
    with pytest.raises(ValueError):
        StatusResultModel.model_validate(mutated)
