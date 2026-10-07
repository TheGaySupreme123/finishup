"""Issue #1012: golden vectors for check `await_observations` and `observations_awaited`."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError
from tests.unit.protocol.test_models_and_schemas import (
    _check_result_wire,  # pyright: ignore[reportPrivateUsage]
)

from yoetz.protocol.canonical import canonical_digest, canonical_encode
from yoetz.protocol.models import CheckRequest, CheckResult, CheckSuccessModel
from yoetz.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance

_FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "fixtures/canonical/check-observations-awaited-1.4.0.case.json"
)

_REQUEST_BASE: dict[str, Any] = {
    "protocol_version": "0.1",
    "schema_version": "1.0.0",
    "request_id": "req_00000000-0000-4000-8000-0000000000d1",
    "session_id": "ses_00000000-0000-4000-8000-0000000000d2",
    "writer_id": "wri_00000000-0000-4000-8000-0000000000d3",
    "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
    "actor": {"actor_id": "harness:test", "actor_type": "harness"},
    "client": {"kind": "test_client", "version": "0.1.0", "integration": "local_cli"},
}


def _vectors() -> list[dict[str, Any]]:
    fixture = cast(dict[str, Any], json.loads(_FIXTURE.read_bytes()))
    assert fixture["fixture_id"] == "CAN-016"
    return cast(list[dict[str, Any]], fixture["input"]["vectors"])


def _admitted(surface: str, payload: dict[str, Any]) -> bool:
    if surface == "check_request":
        instance = {**_REQUEST_BASE, **payload}
        schema = ("check-request", "1.1.0")
        model: Any = CheckRequest
    else:
        instance = {**cast(dict[str, Any], json.loads(json.dumps(_check_result_wire()))), **payload}
        schema = ("check-result", "1.4.0")
        model = CheckResult
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


def test_absent_flag_and_field_keep_their_exact_shapes() -> None:
    request = CheckRequest.model_validate(_REQUEST_BASE)
    assert request.await_observations is None
    result = CheckResult.model_validate(json.loads(json.dumps(_check_result_wire())))
    success = result.root
    assert isinstance(success, CheckSuccessModel)
    assert success.observations_awaited is None
