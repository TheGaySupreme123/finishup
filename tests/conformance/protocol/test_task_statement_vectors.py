"""Golden task-statement vectors hold against the live codecs (issue #908, acceptance 8)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from finishup.adapters.privacy.catalog import (
    decode_privacy_policy_canonical,
    encode_privacy_policy_json,
)
from finishup.application.start import _request_digest  # pyright: ignore[reportPrivateUsage]
from finishup.domain.events import TASK_STATEMENT_EVENT_SCHEMAS, EventSchema, decode_payload
from finishup.domain.events import encode_payload as encode_event_payload
from finishup.domain.values import freeze_json
from finishup.ports.start_catalog import (
    StartCommand,
    StartIdentityCommitments,
    StartIdentityInput,
    StartMode,
)
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.models import MAX_REVIEW_EXCERPTS, StartRequestModel
from finishup.protocol.schemas import validate_schema_instance

_ROOT = Path(__file__).resolve().parents[3]


def _case() -> dict[str, Any]:
    return json.loads((_ROOT / "fixtures/canonical/task-statement.case.json").read_bytes())


def test_event_vectors_round_trip_and_older_versions_refuse_the_statement() -> None:
    vectors = _case()["input"]["event_vectors"]
    assert {(vector["family"], vector["schema_version"]) for vector in vectors} >= {
        (schema.name, schema.version) for schema in TASK_STATEMENT_EVENT_SCHEMAS
    }
    older = {
        vector["family"]: vector["schema_version"]
        for vector in vectors
        if not vector["carries_task_statement"]
    }
    for vector in vectors:
        schema = EventSchema(vector["family"], vector["schema_version"])
        wire = freeze_json(vector["payload"])
        payload = decode_payload(schema, wire)
        encoded = encode_event_payload(payload)
        assert canonical_encode(encoded).hex() == vector["canonical_hex"]
        assert canonical_digest(encoded) == vector["digest"]
        if vector["family"] != "session_resumed":
            # session-resumed's reviewed schema inherits a model-derived frontier shape that the
            # engine-authored wire never matched; its domain codec is authoritative here.
            validate_schema_instance(
                vector["family"].replace("_", "-"), vector["schema_version"], vector["payload"]
            )
        if vector["carries_task_statement"]:
            assert schema in TASK_STATEMENT_EVENT_SCHEMAS
            with pytest.raises(ProtocolValueError):
                decode_payload(EventSchema(vector["family"], older[vector["family"]]), wire)


def test_statement_free_start_keeps_its_digest_and_the_statement_is_identity() -> None:
    case = _case()
    identity = case["input"]["start_request_identity"]
    digests: dict[str, str] = {}
    for variant in identity["variants"]:
        request = StartRequestModel.model_validate(variant["request"])
        command = StartCommand(
            operation_id=request.request_id,
            request_digest="sha256:" + "0" * 64,
            mode=StartMode.CREATE,
            identity_input=StartIdentityInput(task_title=request.task_title),
            identity_commitments=StartIdentityCommitments(**identity["identity_commitments"]),
            repository_privacy_commitment=identity["repository_privacy_commitment"],
        )
        digest = _request_digest(request, command)
        assert digest == variant["request_digest"]
        digests[variant["variant_id"]] = digest
    assert digests["without-statement"] == case["expected"]["statement_free_start_digest"]
    assert len(set(digests.values())) == len(digests)
    released = cast(dict[str, JsonValue], identity["variants"][0]["request"])
    validate_schema_instance("start-request", "1.0.0", released)
    validate_schema_instance("start-request", "1.1.0", identity["variants"][1]["request"])


def test_privacy_policy_wire_keeps_released_bytes_and_adds_the_section_only_in_1_2() -> None:
    wire_case = _case()["input"]["privacy_policy_wire"]
    for vector in wire_case["vectors"]:
        assert vector["wire"]["review_selection"]["max_excerpts"] == vector["max_excerpts"]
        wire = cast(dict[str, JsonValue], vector["wire"])
        validate_schema_instance("privacy-policy", vector["schema_version"], wire)
        policy = decode_privacy_policy_canonical(canonical_encode(wire))
        assert encode_privacy_policy_json(policy) == wire
        assert canonical_digest(wire) == vector["canonical_digest"]
        identity = {key: value for key, value in wire.items() if key != "policy_digest"}
        assert canonical_digest(cast(JsonValue, identity)) == vector["identity_digest"]
        assert ("task_statement" in vector["review_sections"]) == (
            vector["schema_version"] == "1.2.0"
        )
    by_key = {
        (vector["review_context_profile"], vector["preset_version"]): vector
        for vector in wire_case["vectors"]
    }
    for profile in ("goal_aware", "expanded"):
        assert by_key[(profile, "1.1.0")]["schema_version"] == "1.1.0"
        assert by_key[(profile, "1.2.0")]["schema_version"] == "1.2.0"
    # Issue #907 Phase 1b: the Expanded count is 16 under the released wire and the protocol
    # maximum under 1.2.0; the byte budget is the same in both.
    assert by_key[("expanded", "1.1.0")]["max_excerpts"] == 16
    assert by_key[("expanded", "1.2.0")]["max_excerpts"] == MAX_REVIEW_EXCERPTS
    for key in ("max_excerpt_bytes", "max_total_excerpt_bytes"):
        assert (
            by_key[("expanded", "1.1.0")]["wire"]["review_selection"][key]
            == by_key[("expanded", "1.2.0")]["wire"]["review_selection"][key]
        )
