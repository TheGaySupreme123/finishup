"""Review-dialogue event vectors keep legacy bytes and fence the new fields (issue #905)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from yoetz.domain.events import CheckRecordedPayload, EventSchema, decode_payload, encode_payload
from yoetz.domain.findings import Finding, FindingChallenge, finding_to_json
from yoetz.domain.values import freeze_json
from yoetz.protocol.canonical import canonical_digest, canonical_encode
from yoetz.protocol.errors import ProtocolValueError
from yoetz.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance


def _vectors() -> list[dict[str, Any]]:
    path = (
        Path(__file__).resolve().parents[3] / "fixtures/canonical/review-dialogue-1.3.0.case.json"
    )
    return json.loads(path.read_bytes())["input"]["vectors"]


def _schema_rejects(version: str, wire: dict[str, Any]) -> None:
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("finding-recorded", version, wire)


def _findings() -> list[dict[str, Any]]:
    return [vector for vector in _vectors() if vector["family"] == "finding_recorded"]


def _checks() -> list[dict[str, Any]]:
    return [vector for vector in _vectors() if vector["family"] == "check_recorded"]


def test_golden_checks_round_trip_and_rulings_need_their_version() -> None:
    legacy, ruled = _checks()
    for vector in (legacy, ruled):
        version, wire = vector["schema_version"], vector["payload"]
        validate_schema_instance("check-recorded", version, wire)
        payload = decode_payload(EventSchema("check_recorded", version), freeze_json(wire))
        assert type(payload) is CheckRecordedPayload
        encoded = encode_payload(payload)
        assert canonical_encode(encoded).hex() == vector["canonical_hex"]
        assert canonical_digest(encoded) == vector["digest"]
        # The rulings are optional on the unreleased 1.3.0 check: a check without them keeps
        # the bytes an earlier 0.3 build wrote.
        assert version == "1.3.0"
    decoded = decode_payload(EventSchema("check_recorded", "1.3.0"), freeze_json(ruled["payload"]))
    assert type(decoded) is CheckRecordedPayload
    assert [item.verdict for item in decoded.prior_finding_verdicts] == ["unassessable", "fixed"]
    # Released versions never carry rulings (they cannot carry a conclusion either).
    released = {
        key: value for key, value in ruled["payload"].items() if key != "semantic_conclusion"
    }
    with pytest.raises(ProtocolValueError):
        decode_payload(EventSchema("check_recorded", "1.2.0"), freeze_json(released))
    assert legacy["payload"].get("prior_finding_verdicts") is None
    unknown = {
        **ruled["payload"],
        "prior_finding_verdicts": [
            {**ruled["payload"]["prior_finding_verdicts"][0], "verdict": "resolved"}
        ],
    }
    with pytest.raises(ProtocolValueError):
        decode_payload(EventSchema("check_recorded", "1.3.0"), freeze_json(unknown))
    unsorted = {
        **ruled["payload"],
        "prior_finding_verdicts": list(reversed(ruled["payload"]["prior_finding_verdicts"])),
    }
    with pytest.raises(ProtocolValueError):
        decode_payload(EventSchema("check_recorded", "1.3.0"), freeze_json(unsorted))


def test_golden_findings_round_trip_through_schema_and_domain() -> None:
    for vector in _findings():
        version, wire = vector["schema_version"], vector["payload"]
        validate_schema_instance("finding-recorded", version, wire)
        payload = decode_payload(EventSchema("finding_recorded", version), freeze_json(wire))
        assert type(payload) is Finding
        assert version == "1.3.0"
        encoded = encode_payload(payload)
        assert canonical_encode(encoded).hex() == vector["canonical_hex"]
        assert canonical_digest(encoded) == vector["digest"]
        # The public finding wire never carries the event-only dialogue fields.
        public = finding_to_json(payload)
        assert "challenge" not in public
        assert "relates_to" not in public


def test_dialogue_fields_are_optional_on_1_3_0_and_absent_from_released_versions() -> None:
    legacy, restated, _link_only = _findings()
    # A row written by an earlier 0.3 build (no dialogue fields) still reads and validates.
    validate_schema_instance("finding-recorded", "1.3.0", legacy["payload"])
    for version in ("1.1.0", "1.2.0"):
        with pytest.raises(ProtocolValueError):
            decode_payload(
                EventSchema("finding_recorded", version), freeze_json(restated["payload"])
            )
        _schema_rejects(version, restated["payload"])


def test_local_findings_and_malformed_dialogue_fields_are_refused() -> None:
    restated = _findings()[1]["payload"]
    local = {**restated, "origin": "deterministic"}
    local.pop("provenance")
    with pytest.raises(ProtocolValueError):
        decode_payload(EventSchema("finding_recorded", "1.3.0"), freeze_json(local))
    _schema_rejects("1.3.0", local)

    malformed: list[dict[str, Any]] = [
        {**restated, "relates_to": [restated["finding_id"]]},
        {**restated, "relates_to": []},
        {**restated, "challenge": {**restated["challenge"], "requested_next_step": "wait"}},
        {**restated, "challenge": {**restated["challenge"], "discrepancy": ""}},
        {**restated, "challenge": {**restated["challenge"], "extra": "x"}},
    ]
    for wire in malformed:
        with pytest.raises(ProtocolValueError):
            decode_payload(EventSchema("finding_recorded", "1.3.0"), freeze_json(wire))
    oversized = {**restated["challenge"], "uncertainty": "é" * 2049}
    with pytest.raises(ProtocolValueError):
        FindingChallenge(
            oversized["discrepancy"],
            oversized["alternative_interpretation"],
            oversized["requested_next_step"],
            oversized["uncertainty"],
        )


def test_outbound_case_names_the_prior_findings_section_only_from_1_2_0() -> None:
    root = Path(__file__).resolve().parents[3] / "schemas/privacy"
    before = json.loads((root / "outbound-case-1.1.0.schema.json").read_bytes())
    after = json.loads((root / "outbound-case-1.2.0.schema.json").read_bytes())
    assert "prior_finding" not in before["$defs"]["content_item"]["properties"]["section"]["enum"]
    assert "prior_finding" in after["$defs"]["content_item"]["properties"]["section"]["enum"]
    assert "prior_finding_item_ids" not in before["$defs"]["review_packet"]["properties"]
    assert "prior_finding_item_ids" in after["$defs"]["review_packet"]["required"]
    # The rulable list names each earlier finding once, bounded like the ruling array (#905).
    assert "prior_finding_refs" not in before["$defs"]["review_packet"]["properties"]
    assert "prior_finding_refs" in after["$defs"]["review_packet"]["required"]
    refs = after["$defs"]["review_packet"]["properties"]["prior_finding_refs"]
    assert refs["items"] == {"$ref": "#/$defs/finding_id"}
    assert refs["maxItems"] == 8
    assert refs["uniqueItems"] is True
    # No new data category crosses egress with the section.
    assert before["$defs"]["data_category"] == after["$defs"]["data_category"]


_ROOT = Path(__file__).resolve().parents[3] / "schemas"


def _respond_wire(disposition: str, **extra: Any) -> dict[str, Any]:
    wire: dict[str, Any] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": "req_00000000-0000-4000-8000-000000000001",
        "session_id": "ses_00000000-0000-4000-8000-000000000001",
        "writer_id": "wri_00000000-0000-4000-8000-000000000001",
        "expected_frontier": {"sequence": "2", "head_digest": "sha256:" + "a" * 64},
        "finding_id": "fnd_00000000-0000-4000-8000-000000000001",
        "finding_frontier": {"sequence": "2", "head_digest": "sha256:" + "a" * 64},
        "disposition": disposition,
        "actor": {"actor_id": "harness:test", "actor_type": "harness"},
        "client": {"kind": "test_client", "version": "0.1.0", "integration": "local_cli"},
    }
    wire.update(extra)
    return wire


def test_acknowledged_not_done_needs_respond_1_1_0_and_an_old_service_refuses_it() -> None:
    """The released respond 1.0.0 pair and control 2.8.0 never admit the new disposition."""

    reason = {"reason": "Out of scope for this task."}
    validate_schema_instance(
        "respond-request", "1.1.0", _respond_wire("acknowledged_not_done", **reason)
    )
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("respond-request", "1.1.0", _respond_wire("acknowledged_not_done"))
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance(
            "respond-request",
            "1.1.0",
            _respond_wire("acknowledged_not_done", waiver_scope="finding_only", **reason),
        )
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance(
            "respond-request", "1.0.0", _respond_wire("acknowledged_not_done", **reason)
        )
    # Every earlier disposition keeps validating under the new version.
    validate_schema_instance("respond-request", "1.1.0", _respond_wire("acknowledged"))
    control = {
        version: (_ROOT / "service" / f"control-request-{version}.schema.json").read_text()
        for version in ("2.8.0", "2.9.0")
    }
    assert "respond-request-1.0.0" in control["2.8.0"]
    assert "respond-request-1.1.0" not in control["2.8.0"]
    assert "respond-request-1.1.0" in control["2.9.0"]


def test_golden_responses_pin_acknowledged_not_done_on_1_1_0_only() -> None:
    """D6: the terminal disposition's event and wire bytes, beside an unchanged 1.0.0 rejection."""

    responses = [vector for vector in _vectors() if vector["family"] == "response_recorded"]
    assert [(item["schema_version"], item["payload"]["disposition"]) for item in responses] == [
        ("1.0.0", "rejected"),
        ("1.1.0", "acknowledged_not_done"),
        ("1.1.0", "self_verified"),
    ]
    for vector in responses:
        version, wire = vector["schema_version"], vector["payload"]
        validate_schema_instance("response-recorded", version, wire)
        payload = decode_payload(EventSchema("response_recorded", version), freeze_json(wire))
        encoded = encode_payload(payload)
        assert canonical_encode(encoded).hex() == vector["canonical_hex"]
        assert canonical_digest(encoded) == vector["digest"]
    for terminal in (responses[1]["payload"], responses[2]["payload"]):
        with pytest.raises(SchemaInstanceInvalid):
            validate_schema_instance("response-recorded", "1.0.0", terminal)
    # Issue #984: a self-verification without evidence is not admitted even on 1.1.0.
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance(
            "response-recorded", "1.1.0", {**responses[2]["payload"], "evidence_refs": []}
        )
    # The event pairing itself (acknowledged_not_done exactly on 1.1.0) is enforced where an
    # event is drafted or accepted; tests/unit/kernel/test_finding_todo.py locks it.

    path = (
        Path(__file__).resolve().parents[3] / "fixtures/canonical/review-dialogue-1.3.0.case.json"
    )
    operations = json.loads(path.read_bytes())["input"]["operations"]
    assert [(item["schema"], item["schema_version"]) for item in operations] == [
        ("respond-request", "1.1.0"),
        ("respond-result", "1.1.0"),
        ("respond-request", "1.1.0"),
    ]
    for item in operations:
        validate_schema_instance(item["schema"], item["schema_version"], item["payload"])
        with pytest.raises(SchemaInstanceInvalid):
            validate_schema_instance(item["schema"], "1.0.0", item["payload"])
