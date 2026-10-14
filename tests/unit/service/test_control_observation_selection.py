"""Selected observations must traverse the actual framed service boundary (#786)."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, cast

import pytest

from finishup.domain.observation import observation_envelope_from_json
from finishup.protocol.canonical import JsonValue
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance
from finishup.service.control_protocol import (
    ControlProtocolError,
    decode_control_frame,
    encode_control_frame,
)

_FIXTURE = (
    Path(__file__).resolve().parents[3] / "fixtures/observations/routine-read-summary.case.json"
)


def _request(envelope: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": "call",
        "protocol_version": "1.0",
        "rpc_id": "rpc_00000000-0000-4000-8000-000000000001",
        "service_instance_id": "svc_00000000-0000-4000-8000-000000000002",
        "service_generation": "1",
        "method": "observation_ingest",
        "body": {"codex_session_id": "test-native-session", "envelope": envelope},
    }


@pytest.mark.parametrize("kind", ["individual", "summary", "protected"])
def test_existing_selected_observations_round_trip_the_control_frame(kind: str) -> None:
    fixture = json.loads(_FIXTURE.read_bytes())
    envelope = (
        fixture["expected"]["summary_envelope"]
        if kind == "summary"
        else fixture["input"]["envelopes"][0]
    )
    if kind == "protected":
        envelope["structural_payload"]["action"] = "evidence_linked_read"
        envelope["structural_payload"]["protection_reference"] = (
            "obl_00000000-0000-4000-8000-000000000003"
        )
    request = _request(envelope)
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("control-request", "2.6.0", cast(JsonValue, request))
    decoded = decode_control_frame(encode_control_frame(request))
    observed = cast(Any, decoded["body"])["envelope"]
    assert observation_envelope_from_json(observed).source_identity == envelope["source_identity"]
    assert (
        dict(observed["structural_payload"]) == envelope["structural_payload"]
        if kind != "summary"
        else observed["structural_payload"]["input_count"] == 2
    )


@pytest.mark.parametrize(
    "mutation",
    ["partial_route", "foreign_text", "invalid_id", "invalid_generation", "summary_prose"],
)
def test_selection_contract_does_not_admit_incomplete_routes_or_prose(mutation: str) -> None:
    fixture = json.loads(_FIXTURE.read_bytes())
    envelope = copy.deepcopy(
        fixture["expected"]["summary_envelope"]
        if mutation == "summary_prose"
        else fixture["input"]["envelopes"][0]
    )
    fields = envelope["structural_payload"]
    if mutation == "partial_route":
        fields.pop("selection_writer_id")
    elif mutation in {"foreign_text", "summary_prose"}:
        fields["raw_output"] = "must remain excluded"
    elif mutation == "invalid_id":
        fields["selection_task_id"] = "not-a-task"
    else:
        fields["selection_authority_generation"] = "not-a-digest"
    with pytest.raises(ControlProtocolError, match="frame_invalid"):
        encode_control_frame(_request(envelope))
