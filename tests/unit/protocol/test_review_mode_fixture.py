"""ADR-049: golden vectors for the review_mode wire shape of check- and status-result 1.4.0."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError
from tests.unit.protocol.test_models_and_schemas import (
    _check_result_wire,  # pyright: ignore[reportPrivateUsage]
    _status_result_wire,  # pyright: ignore[reportPrivateUsage]
)

from finishup.protocol.canonical import canonical_digest, canonical_encode
from finishup.protocol.models import CheckResult, StatusResult
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance

_FIXTURE = Path(__file__).resolve().parents[3] / "fixtures/canonical/review-mode-1.4.0.case.json"


def _vectors() -> list[dict[str, Any]]:
    fixture = cast(dict[str, Any], json.loads(_FIXTURE.read_bytes()))
    assert fixture["fixture_id"] == "CAN-018"
    return cast(list[dict[str, Any]], fixture["input"]["vectors"])


def _admitted(surface: str, payload: dict[str, Any]) -> bool:
    if surface == "check_result":
        base = cast(dict[str, Any], json.loads(json.dumps(_check_result_wire())))
        schema: tuple[str, str] = ("check-result", "1.4.0")
        model: Any = CheckResult
    else:
        base = cast(dict[str, Any], json.loads(json.dumps(_status_result_wire())))
        schema = ("status-result", "1.4.0")
        model = StatusResult
    instance = {**base, **payload}
    try:
        validate_schema_instance(schema[0], schema[1], instance)
        schema_ok = True
    except SchemaInstanceInvalid:
        schema_ok = False
    try:
        model.model_validate(instance)
        model_ok = True
    except ValidationError:
        model_ok = False
    # The JSON Schema and the pydantic model agree on every vector.
    assert schema_ok == model_ok, payload
    return schema_ok


@pytest.mark.parametrize("vector", _vectors(), ids=lambda vector: str(vector["vector_id"]))
def test_vectors_are_canonical_and_admitted_exactly_as_frozen(vector: dict[str, Any]) -> None:
    payload = cast(dict[str, Any], vector["payload"])
    assert canonical_encode(payload).hex() == vector["canonical_hex"]
    assert canonical_digest(payload) == vector["digest"]
    assert _admitted(cast(str, vector["surface"]), payload) is vector["admitted"]


def test_the_vectors_cover_the_round_two_shape() -> None:
    ids = {vector["vector_id"]: vector for vector in _vectors()}
    assert ids["check_local_review_disabled"]["admitted"] is True
    assert ids["status_without_setting_explicit"]["admitted"] is False
    assert ids["status_released_local_only"]["payload"]["review_mode"]["setting_explicit"] is False
