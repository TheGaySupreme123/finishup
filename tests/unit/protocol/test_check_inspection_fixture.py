"""Issue #1048 (ADR-047): golden vectors for the read-only check mode ``inspect``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from finishup.protocol.canonical import canonical_digest, canonical_encode
from finishup.protocol.inspection_text import inspection_text
from finishup.protocol.models import CheckInspectionModel, CheckRequest, CheckResult
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance

_FIXTURE = (
    Path(__file__).resolve().parents[3] / "fixtures/canonical/check-inspection-1.4.0.case.json"
)

_REQUEST_BASE: dict[str, Any] = {
    "protocol_version": "0.1",
    "schema_version": "1.0.0",
    "request_id": "req_00000000-0000-4000-8000-0000000000f1",
    "session_id": "ses_00000000-0000-4000-8000-0000000000f2",
    "writer_id": "wri_00000000-0000-4000-8000-0000000000f3",
    "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
    "actor": {"actor_id": "harness:test", "actor_type": "harness"},
    "client": {"kind": "test_client", "version": "0.1.0", "integration": "local_cli"},
}
_PRIVACY_PROJECTION: dict[str, Any] = {
    "sink": "agent_context",
    "local_disclosure_receipt_id": "egr_00000000-0000-4000-8000-0000000000f4",
    "policy_id": "pvy_00000000-0000-4000-8000-0000000000f5",
    "policy_version": "1",
    "policy_digest": "sha256:" + "0" * 64,
    "included_categories": [],
    "blocked_categories": [],
    "omitted_pointers": [],
    "projection_commitment": "hmac-sha256:" + "1" * 64,
}


def _vectors() -> list[dict[str, Any]]:
    fixture = cast(dict[str, Any], json.loads(_FIXTURE.read_bytes()))
    assert fixture["fixture_id"] == "CAN-017"
    return cast(list[dict[str, Any]], fixture["input"]["vectors"])


def _instance(surface: str, payload: dict[str, Any]) -> tuple[dict[str, Any], tuple[str, str]]:
    if surface == "check_request":
        return {**_REQUEST_BASE, **payload}, ("check-request", "1.1.0")
    return {**payload, "privacy_projection": _PRIVACY_PROJECTION}, ("check-result", "1.4.0")


@pytest.mark.parametrize("vector", _vectors(), ids=lambda vector: str(vector["vector_id"]))
def test_vectors_are_canonical_and_admitted_exactly_as_frozen(vector: dict[str, Any]) -> None:
    payload = cast(dict[str, Any], vector["payload"])
    assert canonical_encode(payload).hex() == vector["canonical_hex"]
    assert canonical_digest(payload) == vector["digest"]
    instance, schema = _instance(cast(str, vector["surface"]), payload)
    try:
        validate_schema_instance(schema[0], schema[1], instance)
        schema_ok = True
    except SchemaInstanceInvalid:
        schema_ok = False
    model: Any = CheckRequest if vector["surface"] == "check_request" else CheckResult
    try:
        model.model_validate(instance)
        model_ok = True
    except ValidationError:
        model_ok = False
    assert schema_ok is vector["schema_admitted"]
    assert model_ok is vector["admitted"]


def test_the_admitted_branch_discriminates_and_renders_without_text_from_the_case() -> None:
    (vector,) = [item for item in _vectors() if item["vector_id"] == "result_inspection"]
    instance, _ = _instance("check_result", cast(dict[str, Any], vector["payload"]))
    result = CheckResult.model_validate(instance)
    assert type(result.root) is CheckInspectionModel
    text = inspection_text(instance)
    rendered = "\n".join((*text.lead, *text.details))
    assert "What is left: readiness action_required" in rendered
    assert "requested items not attempted (#0) [you]" in rendered
    assert "asserted command run has no linked hook observation (#1) [FinishUP]" in rendered
    assert "evidence_off_declared_items" in rendered
    assert "FinishUP records no command text" in rendered
