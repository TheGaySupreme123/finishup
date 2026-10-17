"""Golden vectors for the ADR-050 wire additions (issue #1084, fixture CAN-022).

The generator ``scripts/generate_publish_server_filled_fixture.py`` owns the bytes and the resource
ripple checks them; this test reads the committed vectors and admits each exactly as frozen
against the closed JSON schema and the public result model, then reads the brief and labelled
vectors through the agent-facing text renderer.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from finishup.mcp.summaries import render_safe_compact_summary
from finishup.protocol.canonical import canonical_digest, canonical_encode
from finishup.protocol.models import PublishWorkResultModel, StatusResultModel
from finishup.protocol.publish_boilerplate import server_filled_from_json
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance

_FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "fixtures/canonical/server-filled-brief-status-1.4.0.case.json"
)
_VERSIONS = {"publish-work-result": "1.1.0", "status-result": "1.4.0"}
_MODELS: dict[str, Any] = {
    "publish-work-result": PublishWorkResultModel,
    "status-result": StatusResultModel,
}


def _vectors() -> list[dict[str, Any]]:
    fixture = cast(dict[str, Any], json.loads(_FIXTURE.read_bytes()))
    assert fixture["fixture_id"] == "CAN-022"
    return cast(list[dict[str, Any]], fixture["input"]["vectors"])


def _by_id() -> dict[str, dict[str, Any]]:
    return {str(vector["vector_id"]): vector for vector in _vectors()}


@pytest.mark.parametrize("vector", _vectors(), ids=lambda vector: str(vector["vector_id"]))
def test_vectors_are_canonical_and_admitted_exactly_as_frozen(vector: dict[str, Any]) -> None:
    payload = cast(dict[str, Any], vector["payload"])
    assert canonical_encode(payload).hex() == vector["canonical_hex"]
    assert canonical_digest(payload) == vector["digest"]
    schema = cast(str, vector["schema"])
    try:
        validate_schema_instance(schema, _VERSIONS[schema], payload)
        schema_ok = True
    except SchemaInstanceInvalid:
        schema_ok = False
    try:
        _MODELS[schema].model_validate(payload)
        model_ok = True
    except ValidationError:
        model_ok = False
    assert schema_ok is vector["schema_admitted"]
    assert model_ok is vector["admitted"]


def test_the_admitted_records_decode_and_never_name_a_request_id() -> None:
    for vector_id in (
        "publish_sparse_success_filled",
        "publish_dry_run_filled",
        "publish_reduced_replay_filled",
    ):
        record = server_filled_from_json(_by_id()[vector_id]["payload"]["server_filled"])
        assert record.request == ("expected_frontier",)
        assert record.filled_time_indexes() == frozenset({0, 1})
    assert "server_filled" not in _by_id()["publish_complete_body_no_record"]["payload"]


def test_the_text_surface_reads_the_brief_and_labelled_vectors() -> None:
    brief = _by_id()["status_brief_history_service_clock_label"]["payload"]
    text = render_safe_compact_summary(brief)
    assert "Closure: action_required." in text
    assert "Agent-actionable: obligations_open, check_not_recorded." in text
    assert "unavailable" not in text
    items = brief["page"]["items"]
    assert [item.get("occurred_at_source") for item in items] == ["service_clock", None]
    published = render_safe_compact_summary(_by_id()["publish_sparse_success_filled"]["payload"])
    assert "service-filled: artifact_refs, causal_parents, event_id" in published
