"""Control 2.10 workspace-binding golden vectors (ADR-051) decode on the active wire."""

from __future__ import annotations

import json
from typing import Any, cast

import pytest

from finishup.domain.observation import (
    observation_ingest_request_from_json,
    observation_ingest_request_to_json,
)
from finishup.domain.values import freeze_json
from finishup.ports.workspace_agent import WORKSPACE_OPERATION_CATALOG, WorkspaceOperation
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.schemas import validate_schema_instance
from finishup.service.control_protocol import (
    decode_control_frame,
    encode_control_frame,
    is_workspace_call_frame,
    is_workspace_reply_frame,
    parse_workspace_call,
    parse_workspace_reply,
)
from fixture_loader import FixtureLoader

_SINGLE = (
    ("canonical/control-hello-locator-2.10.case.json", "CTL-2100", "control-hello"),
    ("canonical/control-hello-claim-2.10.case.json", "CTL-2101", "control-hello"),
    ("canonical/control-hello-result-claim-2.10.case.json", "CTL-2102", "control-hello-result"),
)
_EXCHANGES = (
    ("canonical/control-workspace-git-2.10.case.json", "CTL-2103", "git"),
    ("canonical/control-workspace-reads-2.10.case.json", "CTL-2104", "reads"),
    ("canonical/control-workspace-observation-2.10.case.json", "CTL-2105", "observation"),
)


def _assert_frame(frame: dict[str, JsonValue], expected: dict[str, Any]) -> None:
    assert canonical_encode(frame).hex() == expected["canonical_hex"]
    assert len(canonical_encode(frame)) == expected["canonical_byte_length"]
    assert canonical_digest(frame) == expected["canonical_sha256"]
    assert canonical_encode(decode_control_frame(encode_control_frame(frame))) == (
        canonical_encode(frame)
    )


@pytest.mark.parametrize(("path", "fixture_id", "schema_name"), _SINGLE)
def test_handshake_vectors_are_valid_2_10_frames(
    fixture_loader: FixtureLoader, path: str, fixture_id: str, schema_name: str
) -> None:
    fixture = cast(dict[str, Any], fixture_loader.load_json(path))
    assert fixture["fixture_id"] == fixture_id
    assert fixture["minimum_versions"]["control_schema"] == "2.10.0"
    frame = cast(dict[str, JsonValue], fixture["input"]["frame"])
    assert fixture["expected"]["schema_name"] == schema_name
    validate_schema_instance(schema_name, "2.10.0", frame)
    _assert_frame(frame, fixture["expected"])


def test_the_claim_vectors_are_new_in_2_10_and_the_locator_vector_is_not(
    fixture_loader: FixtureLoader,
) -> None:
    locator, claim, result = (
        cast(dict[str, Any], fixture_loader.load_json(path))["input"]["frame"]
        for path, _, _ in _SINGLE
    )
    # The local hello keeps its 2.9 members exactly; only the claim-bound frames need 2.10.
    validate_schema_instance("control-hello", "2.9.0", locator)
    assert "workspace_claim" not in locator and "workspace_agent" not in locator
    with pytest.raises(ProtocolValueError):
        validate_schema_instance("control-hello", "2.9.0", claim)
    with pytest.raises(ProtocolValueError):
        validate_schema_instance("control-hello-result", "2.9.0", result)
    assert "workspace_locator" not in claim
    assert result["workspace_binding"] == "client_claim"
    assert result["workspace_handle"].startswith("client:")


def test_a_workspace_handle_rides_only_a_client_claim_binding(
    fixture_loader: FixtureLoader,
) -> None:
    fixture = cast(
        dict[str, Any],
        fixture_loader.load_json("canonical/control-hello-result-claim-2.10.case.json"),
    )
    result = cast(dict[str, JsonValue], fixture["input"]["frame"])
    # The client rejects a handle on any other binding; so does the contract.
    for binding in ("none", "local_path"):
        with pytest.raises(ProtocolValueError):
            validate_schema_instance(
                "control-hello-result", "2.10.0", {**result, "workspace_binding": binding}
            )
    unbound = {key: value for key, value in result.items() if key != "workspace_binding"}
    with pytest.raises(ProtocolValueError):
        validate_schema_instance("control-hello-result", "2.10.0", unbound)
    # Admitted answers without a handle, and the manifest-mismatch answer, which keeps the frozen
    # pre-2.10 shape with neither member, stay valid.
    without_handle = {key: value for key, value in result.items() if key != "workspace_handle"}
    for binding in ("none", "local_path", "client_claim"):
        validate_schema_instance(
            "control-hello-result", "2.10.0", {**without_handle, "workspace_binding": binding}
        )
    mismatch = {
        key: value
        for key, value in result.items()
        if key not in {"workspace_binding", "workspace_handle"}
    }
    validate_schema_instance("control-hello-result", "2.10.0", mismatch)


@pytest.mark.parametrize(("path", "fixture_id", "family"), _EXCHANGES)
def test_each_family_exchange_decodes_through_the_catalog(
    fixture_loader: FixtureLoader, path: str, fixture_id: str, family: str
) -> None:
    fixture = cast(dict[str, Any], fixture_loader.load_json(path))
    assert fixture["fixture_id"] == fixture_id
    assert fixture["expected"]["family"] == family
    vectors = fixture["input"]["vectors"]
    expected = {item["vector_id"]: item for item in fixture["expected"]["vectors"]}
    assert len(vectors) == len(expected) >= 2
    outcomes: set[str] = set()
    for vector in vectors:
        call_frame = cast(dict[str, JsonValue], vector["call"])
        reply_frame = cast(dict[str, JsonValue], vector["reply"])
        _assert_frame(call_frame, expected[vector["vector_id"]]["call"])
        _assert_frame(reply_frame, expected[vector["vector_id"]]["reply"])
        decoded_call = decode_control_frame(encode_control_frame(call_frame))
        decoded_reply = decode_control_frame(encode_control_frame(reply_frame))
        assert is_workspace_call_frame(decoded_call)
        assert is_workspace_reply_frame(decoded_reply)
        call = parse_workspace_call(decoded_call)
        reply = parse_workspace_reply(decoded_reply)
        assert reply.call_id == call.call_id
        spec = WORKSPACE_OPERATION_CATALOG[WorkspaceOperation(call.operation)]
        assert spec.family == family
        arguments = spec.decode_arguments(call.arguments)
        assert canonical_encode(spec.encode_arguments(arguments)) == canonical_encode(
            call_frame["arguments"]
        )
        outcomes.add(reply.outcome)
        if reply.outcome == "ok":
            result = spec.decode_result(reply.result)
            assert canonical_encode(spec.encode_result(result)) == canonical_encode(
                reply_frame["result"]
            )
        else:
            assert reply.result is None and reply.reason is not None
    assert "ok" in outcomes and outcomes - {"ok"}


def test_the_attested_ingest_vector_is_a_2_10_request_with_no_path(
    fixture_loader: FixtureLoader,
) -> None:
    """CTL-2106: a claim-bound ingest carries the client's attestation (ADR-051 decision 12)."""

    path = "canonical/control-observation-ingest-attested-2.10.case.json"
    fixture = cast(dict[str, Any], fixture_loader.load_json(path))
    assert fixture["fixture_id"] == "CTL-2106"
    assert fixture["expected"]["schema_name"] == "control-request"
    frame = cast(dict[str, JsonValue], fixture["input"]["frame"])
    validate_schema_instance("control-request", "2.10.0", frame)
    _assert_frame(frame, fixture["expected"])
    # The member is new in 2.10; an unattested ingest keeps its 2.9 shape.
    with pytest.raises(ProtocolValueError):
        validate_schema_instance("control-request", "2.9.0", frame)
    body = cast(dict[str, Any], frame["body"])
    unattested = {**frame, "body": {k: v for k, v in body.items() if k != "client_attestation"}}
    validate_schema_instance("control-request", "2.9.0", cast(dict[str, JsonValue], unattested))
    request = observation_ingest_request_from_json(freeze_json(body))
    attestation = request.client_attestation
    assert attestation is not None and attestation.consent == "active"
    assert attestation.route is not None
    assert canonical_encode(observation_ingest_request_to_json(request)) == canonical_encode(
        cast(JsonValue, body)
    )
    assert "/" not in json.dumps(body["client_attestation"])
