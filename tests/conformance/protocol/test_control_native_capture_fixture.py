"""Manifest-bound positive vectors for the additive native capture control wire."""

from __future__ import annotations

from typing import Any, cast

from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.protocol.schemas import validate_schema_instance
from fixture_loader import FixtureLoader

_FIXTURE = "canonical/control-native-capture-2.5.case.json"


def test_manifest_bound_claude_and_cursor_capture_vectors_are_canonical(
    fixture_loader: FixtureLoader,
) -> None:
    document = cast(dict[str, Any], fixture_loader.load_json(_FIXTURE))
    assert document["fixture_id"] == "CTL-250"
    assert document["fixture_schema"] == "yoetz.fixture-case/1.0.0"
    assert document["fixture_version"] == "1.0.0"

    input_document = cast(dict[str, Any], document["input"])
    expected_document = cast(dict[str, Any], document["expected"])
    vectors = cast(list[dict[str, Any]], input_document["vectors"])
    expected_vectors = cast(list[dict[str, Any]], expected_document["vectors"])
    assert len(vectors) == len(expected_vectors) == 3
    assert expected_document["outer_protocol_version"] == "1.0"
    assert expected_document["schema_version"] == "2.5.0"

    for vector, expected in zip(vectors, expected_vectors, strict=True):
        request = cast(dict[str, Any], vector["request"])
        request_json = cast(JsonValue, request)
        validate_schema_instance("control-request", "2.5.0", request_json)
        encoded = canonical_encode(request_json)
        assert len(encoded) == expected["canonical_byte_length"]
        assert encoded.hex() == expected["canonical_hex"]
        assert canonical_digest(request_json) == expected["canonical_sha256"]

        identity = cast(dict[str, Any], expected["request_identity"])
        result = cast(dict[str, Any], expected["expected_result"])
        body = cast(dict[str, Any], request["body"])
        envelope = cast(dict[str, Any], body["envelope"])
        assert request["method"] == identity["method"] == "observation_ingest"
        assert request["rpc_id"] == identity["rpc_id"]
        assert request["service_generation"] == identity["service_generation"] == "1"
        assert request["service_instance_id"] == identity["service_instance_id"]
        assert request["protocol_version"] == result["protocol_version"] == "1.0"
        assert body["capture_only"] is result["capture_only"] is True
        if "content_capture_profile" in body:
            assert body["content_capture_profile"] == result["content_capture_profile"]
        else:
            assert "content_capture_profile" not in result
        assert envelope["source"] == result["source"]
        assert result["schema_validation"] == "valid"
        assert result["service_result"] == {
            "advanced_cursor": None,
            "disposition": "rejected",
            "reason": "content_capture_pending",
        }
        assert result["schema_name"] == "control-request"
        assert result["schema_version"] == "2.5.0"
