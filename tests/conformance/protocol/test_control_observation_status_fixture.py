"""The observation-status selection projections are frozen wire vectors.

CTL-260 freezes the additive 2.6 projection; CTL-290 freezes the 2.9 configurable-capacity
projection (custom queue count, capacity labels, effective budget) that the live codec speaks.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from finishup.domain.observation import observation_status_from_json
from finishup.domain.values import freeze_json
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.schemas import validate_schema_instance
from finishup.service.control_protocol import decode_control_frame, encode_control_frame
from fixture_loader import FixtureLoader

_FIXTURE = "canonical/control-observation-status-2.6.case.json"
_FIXTURE_29 = "canonical/control-observation-status-2.9.case.json"
_SCHEMA_ROOT = Path(__file__).parents[3] / "schemas"


def _document(fixture_loader: FixtureLoader, path: str = _FIXTURE) -> dict[str, Any]:
    return cast(dict[str, Any], fixture_loader.load_json(path))


def test_selection_runtime_status_is_valid_only_on_additive_26_wire(
    fixture_loader: FixtureLoader,
) -> None:
    document = _document(fixture_loader)
    expected = cast(dict[str, Any], document["expected"])
    frame = cast(dict[str, JsonValue], cast(dict[str, Any], document["input"])["frame"])

    validate_schema_instance("control-result", "2.6.0", frame)
    with pytest.raises(ProtocolValueError):
        validate_schema_instance("control-result", "2.5.0", frame)

    encoded = canonical_encode(frame)
    assert len(encoded) == expected["canonical_byte_length"]
    assert encoded.hex() == expected["canonical_hex"]
    assert canonical_digest(frame) == expected["canonical_sha256"]

    status = cast(dict[str, Any], cast(dict[str, Any], frame["body"])["status"])
    assert "selection_runtime" in status
    assert expected["selection_runtime_present"] is True


def test_custom_capacity_status_is_valid_only_on_29_wire_and_round_trips(
    fixture_loader: FixtureLoader,
) -> None:
    document = _document(fixture_loader, _FIXTURE_29)
    assert document["fixture_id"] == "CTL-290"
    assert document["minimum_versions"]["control_schema"] == "2.9.0"
    expected = cast(dict[str, Any], document["expected"])
    assert (expected["old_schema_version"], expected["new_schema_version"]) == ("2.8.0", "2.9.0")
    frame = cast(dict[str, JsonValue], cast(dict[str, Any], document["input"])["frame"])

    validate_schema_instance("control-result", "2.9.0", frame)
    with pytest.raises(ProtocolValueError):
        validate_schema_instance("control-result", "2.8.0", frame)

    encoded = canonical_encode(frame)
    assert len(encoded) == expected["canonical_byte_length"]
    assert encoded.hex() == expected["canonical_hex"]
    assert canonical_digest(frame) == expected["canonical_sha256"]

    decoded = decode_control_frame(encode_control_frame(frame))
    assert canonical_encode(decoded) == encoded
    status = cast(dict[str, Any], cast(dict[str, Any], frame["body"])["status"])
    assert "selection_runtime" in status
    assert expected["selection_runtime_present"] is True

    decoded_body = cast(dict[str, JsonValue], cast(dict[str, JsonValue], decoded)["body"])
    runtime = observation_status_from_json(freeze_json(decoded_body["status"])).selection_runtime
    assert runtime is not None
    assert runtime.selected_capacity.queue_count == 1024
    assert runtime.effective_capacity.queue_count == 1024
    assert runtime.selected_capacity_label == "custom"
    assert runtime.effective_capacity_label == "custom"
    budget = cast(dict[str, Any], runtime.effective_budget)
    assert budget["scope"] == "session"
    assert budget["effective_reason"] == "selected"
    assert budget["selected_queue_count"] == budget["effective_queue_count"] == 1024
    assert budget["limits"]["queue_count"] == 1024
    assert budget["no_cap"]["available"] is False
    assert budget["no_cap"]["reason"] == "state_document_ceiling"


def test_released_26_control_result_retains_its_workflow_result_schemas() -> None:
    document = cast(
        dict[str, Any],
        strict_json_parse((_SCHEMA_ROOT / "service/control-result-2.6.0.schema.json").read_bytes()),
    )
    refs: set[str] = set()

    def collect(value: object) -> None:
        if isinstance(value, dict):
            mapping = cast(dict[str, object], value)
            ref = mapping.get("$ref")
            if isinstance(ref, str):
                refs.add(ref)
            for child in mapping.values():
                collect(child)
        elif isinstance(value, list):
            for child in cast(list[object], value):
                collect(child)

    collect(document)
    assert "https://schemas.yoetz.dev/0.1/operations/check-result-1.2.0.schema.json" in refs
    assert "https://schemas.yoetz.dev/0.1/operations/receipt-result-1.2.0.schema.json" in refs
    assert "https://schemas.yoetz.dev/0.1/operations/status-result-1.3.0.schema.json" in refs
    assert "https://schemas.yoetz.dev/0.1/operations/check-result-1.1.0.schema.json" not in refs
    assert "https://schemas.yoetz.dev/0.1/operations/receipt-result-1.1.0.schema.json" not in refs
    assert "https://schemas.yoetz.dev/0.1/operations/status-result-1.2.0.schema.json" not in refs
