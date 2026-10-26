"""Optional agent-declared result manifests preserve old bytes and reject misleading counts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from finishup.domain.events import (
    EventDraft,
    EventSchema,
    ResultOutcome,
    ResultRecordedPayload,
    ResultVerification,
    VerificationDataSource,
    VerificationExpectedFrom,
    decode_payload,
    encode_payload,
)
from finishup.domain.values import JsonValue, action_id, event_id, result_id, timestamp_from_string
from finishup.protocol.canonical import canonical_digest, canonical_encode
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance

_FIXTURE = (
    Path(__file__).resolve().parents[3] / "fixtures/canonical/result-verification-1.1.0.case.json"
)


def test_manifest_golden_vectors_and_frozen_legacy_contract() -> None:
    fixture = json.loads(_FIXTURE.read_bytes())
    for vector in fixture["input"]["vectors"]:
        wire = vector["payload"]
        assert canonical_encode(wire).hex() == vector["canonical_hex"]
        assert canonical_digest(wire) == vector["digest"]
        for version, admitted in (
            ("1.0.0", vector["admitted_1_0"]),
            ("1.1.0", vector["admitted_1_1"]),
        ):
            if admitted:
                payload = decode_payload(EventSchema("result_recorded", version), wire)
                assert canonical_encode(encode_payload(payload)) == canonical_encode(wire)
            else:
                with pytest.raises(ProtocolValueError):
                    decode_payload(EventSchema("result_recorded", version), wire)
            # JSON Schema cannot express failing <= cases. Domain admission owns that relation.
            schema_admitted = admitted or (
                version == "1.1.0" and vector["vector_id"] == "failing_exceeds_cases"
            )
            if schema_admitted:
                validate_schema_instance("result-recorded", version, wire)
            else:
                with pytest.raises(SchemaInstanceInvalid):
                    validate_schema_instance("result-recorded", version, wire)


@pytest.mark.parametrize(
    "changes",
    [
        {"criterion_quote": ""},
        {"criterion_quote": "x" * 241},
        {"criterion_quote": "\x00"},
        {"cases": -1},
        {"cases": 2**53},
        {"failing": -1},
        {"cases": 1, "failing": 2},
        {"worst": "x" * 65},
        {"tuned_on_these_cases": 1},
        {"test_file": "test.py"},
        {"report_digest": "sha256:" + "a" * 64},
        {"test_file": "test.py", "results_file": "results.json", "report_digest": "bad"},
        {"checks": ""},
        {"checks": " "},
        {"checks": "x" * 201},
        {"expected_from": "from_memory"},
    ],
)
def test_domain_bounds_and_registration_pair(changes: dict[str, Any]) -> None:
    fields: dict[str, Any] = {
        "criterion_quote": "condition",
        "data_source": VerificationDataSource.UNKNOWN,
        "cases": 1,
        "failing": 0,
    }
    with pytest.raises(ProtocolValueError):
        ResultVerification(**{**fields, **changes})


def test_typed_draft_cannot_put_manifest_on_released_schema() -> None:
    payload = ResultRecordedPayload(
        result_id("res_00000000-0000-4000-8000-000000001170"),
        action_id("act_00000000-0000-4000-8000-000000001170"),
        ResultOutcome.SUCCESS,
        verification=ResultVerification("condition", VerificationDataSource.HELD_OUT, 2, 0),
    )
    with pytest.raises(ProtocolValueError, match="invalid_event_schema"):
        EventDraft(
            event_id("evt_00000000-0000-4000-8000-000000001170"),
            EventSchema("result_recorded", "1.0.0"),
            timestamp_from_string("2026-10-21T10:00:00.000Z"),
            (),
            payload,
            (),
            (),
        )


_TAGGED_WIRE: dict[str, Any] = {
    "result_id": "res_00000000-0000-4000-8000-000000001219",
    "action_id": "act_00000000-0000-4000-8000-000000001219",
    "outcome": "success",
    "verification": {
        "criterion_quote": "condition",
        "data_source": "own_generated",
        "cases": 3,
        "failing": 0,
        "checks": "x" * 200,
        "expected_from": "implementation_output",
    },
}


def test_checks_and_expected_from_round_trip_on_the_manifest_version_only() -> None:
    # Issue #1219: both optional fields are admitted in place on the unreleased 1.1.0 manifest.
    payload = decode_payload(EventSchema("result_recorded", "1.1.0"), cast(JsonValue, _TAGGED_WIRE))
    assert isinstance(payload, ResultRecordedPayload)
    assert payload.verification is not None
    assert payload.verification.checks == "x" * 200
    assert payload.verification.expected_from is VerificationExpectedFrom.IMPLEMENTATION_OUTPUT
    assert canonical_encode(encode_payload(payload)) == canonical_encode(_TAGGED_WIRE)
    validate_schema_instance("result-recorded", "1.1.0", _TAGGED_WIRE)
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("result-recorded", "1.0.0", _TAGGED_WIRE)
    # The domain enum, the schema enum and the projection vocabulary are one closed set.
    from finishup.domain.verification_coverage import VERIFICATION_EXPECTED_FROM

    assert tuple(item.value for item in VerificationExpectedFrom) == VERIFICATION_EXPECTED_FROM


def test_a_manifest_without_the_new_fields_keeps_its_bytes() -> None:
    wire = {
        **_TAGGED_WIRE,
        "verification": {
            key: value
            for key, value in _TAGGED_WIRE["verification"].items()
            if key not in {"checks", "expected_from"}
        },
    }
    payload = decode_payload(EventSchema("result_recorded", "1.1.0"), cast(JsonValue, wire))
    assert canonical_encode(encode_payload(payload)) == canonical_encode(wire)
    assert b"checks" not in canonical_encode(encode_payload(payload))
    assert b"expected_from" not in canonical_encode(encode_payload(payload))


@pytest.mark.parametrize(
    "change",
    [
        {"expected_from": "from_memory"},
        {"expected_from": "TASK_TEXT"},
        {"checks": ""},
        {"checks": " "},
        {"checks": "x" * 201},
        {"checks": 7},
    ],
)
def test_bad_checks_or_expected_from_is_refused_by_schema_and_domain(
    change: dict[str, Any],
) -> None:
    wire = {**_TAGGED_WIRE, "verification": {**_TAGGED_WIRE["verification"], **change}}
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("result-recorded", "1.1.0", wire)
    with pytest.raises(ProtocolValueError):
        decode_payload(EventSchema("result_recorded", "1.1.0"), cast(JsonValue, wire))
