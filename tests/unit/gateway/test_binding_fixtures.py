"""Golden cases of the HTTPS binding v1: server-info, rest-error, the synthesized refusal.

``fixtures/service/rest-*.case.json`` lock the exact bytes the gateway produces for a transport
failure and for an out-of-scope call (a ``method_forbidden`` control-result built from the
session's service instance and generation, byte-shaped like a daemon error result), and a
``server-info`` 1.0.0 document. Each validates against its schema and its contract model.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from finishup.gateway import app as gateway_app
from finishup.gateway.sessions import GatewaySession
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.rest_binding import (
    REST_ERROR_STATUS,
    RestErrorContract,
    ServerInfoContract,
)
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance
from finishup.service.control_protocol import decode_control_frame

_FIXTURES = Path(__file__).parents[3] / "fixtures" / "service"


def _case(name: str) -> bytes:
    return (_FIXTURES / name).read_bytes()


def test_the_server_info_golden_case_is_canonical_and_valid() -> None:
    data = _case("rest-server-info.case.json")
    document = cast(dict[str, JsonValue], json.loads(data))
    assert canonical_encode(document) == data
    validate_schema_instance("server-info", "1.0.0", document)
    ServerInfoContract.model_validate(document)
    for field in ("label", "host", "base_url", "secret"):
        assert field not in document
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("server-info", "1.0.0", {**document, "scope": "owner"})


def test_the_rest_error_golden_case_matches_the_gateways_bytes() -> None:
    data = _case("rest-error.case.json")
    document = cast(dict[str, JsonValue], json.loads(data))
    validate_schema_instance("rest-error", "1.0.0", document)
    RestErrorContract.model_validate(document)
    assert gateway_app._error_body("session_unknown") == data  # pyright: ignore[reportPrivateUsage]
    for reason in REST_ERROR_STATUS:
        body = json.loads(gateway_app._error_body(reason))  # pyright: ignore[reportPrivateUsage]
        validate_schema_instance("rest-error", "1.0.0", body)
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("rest-error", "1.0.0", {**document, "reason": "lab.example"})


def test_the_synthesized_refusal_is_byte_identical_to_its_golden_case() -> None:
    data = _case("rest-method-forbidden.case.json")
    frame = decode_control_frame(len(data).to_bytes(4, "big") + data)
    validate_schema_instance("control-result", "2.10.0", cast(JsonValue, frame))
    session = GatewaySession(
        sid="s" * 43,
        key_id="0123456789ab",
        scope="agent",
        claim_bound=False,
        agent=False,
        upstream=cast(object, None),  # pyright: ignore[reportArgumentType]
        service_instance_id="svc_00000000-0000-4000-8000-000000000210",
        service_generation="1",
    )
    call: dict[str, JsonValue] = {
        "kind": "call",
        "protocol_version": "1.0",
        "rpc_id": "rpc_00000000-0000-4000-8000-000000000210",
        "service_instance_id": "svc_00000000-0000-4000-8000-000000000210",
        "service_generation": "1",
        "method": "service_lock",
        "body": {},
    }
    produced = gateway_app._forbidden_result(session, call)  # pyright: ignore[reportPrivateUsage,reportArgumentType]
    assert produced == data
