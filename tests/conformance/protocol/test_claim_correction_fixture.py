"""Manifest-bound wire vector for append-only claim correction."""

from __future__ import annotations

from typing import Any, cast

import pytest

from finishup.domain.events import ClaimRecordedPayloadV1_1, EventSchema, decode_payload
from finishup.domain.values import freeze_json
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance
from fixture_loader import load_fixture_json


def test_claim_correction_fixture_freezes_canonical_replacement_shape() -> None:
    document = cast(dict[str, Any], load_fixture_json("canonical/claim-correction-1.1.0.case.json"))
    replacement = cast(dict[str, Any], cast(dict[str, Any], document["input"])["replacement_claim"])
    schema_wire = cast(dict[str, str], replacement["schema"])
    payload_wire = freeze_json(replacement["payload"])

    assert schema_wire == {"name": "claim_recorded", "version": "1.1.0"}
    validate_schema_instance("claim-recorded", "1.1.0", payload_wire)
    payload = decode_payload(EventSchema("claim_recorded", "1.1.0"), payload_wire)
    assert type(payload) is ClaimRecordedPayloadV1_1

    expected = cast(dict[str, Any], document["expected"])
    assert list(payload.supersedes_claim_refs) == expected["historical_claim_ids"][:1]
    assert list(payload.limitation_refs) == [expected["status_result"]["result_id"]]
    assert expected["effective_claim_ids"] == [payload.claim_id]
    assert expected["invalid_replacements"] == [
        {"field": "limitation_refs", "invariant": "limitation_refs_complete"},
        {"field": "disputes_refs", "invariant": "replacement_must_not_dispute"},
        {"field": "supersedes_claim_refs", "invariant": "superseded_claim_must_be_effective"},
    ]


def test_claim_correction_adds_exact_authoring_without_changing_opaque_compatibility() -> None:
    document = cast(dict[str, Any], load_fixture_json("canonical/claim-correction-1.1.0.case.json"))
    replacement = cast(dict[str, Any], cast(dict[str, Any], document["input"])["replacement_claim"])
    draft = freeze_json(
        {
            "event_id": "evt_00000000-0000-4000-8000-000000000202",
            "schema": replacement["schema"],
            "occurred_at": "2026-08-30T00:00:00.000Z",
            "causal_parents": [],
            "payload": replacement["payload"],
            "artifact_refs": [],
            "evidence_refs": [],
        }
    )
    request = freeze_json(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": "req_00000000-0000-4000-8000-000000000202",
            "session_id": "ses_00000000-0000-4000-8000-000000000202",
            "writer_id": "wri_00000000-0000-4000-8000-000000000202",
            "expected_frontier": {"sequence": "1", "head_digest": "sha256:" + "1" * 64},
            "event_drafts": [draft],
            "actor": {"actor_id": "harness:claim-correction", "actor_type": "harness"},
            "client": {
                "kind": "cooperative_agent",
                "version": "0.1.0",
                "integration": "cooperative_mcp",
            },
        }
    )
    control = freeze_json(
        {
            "kind": "call",
            "protocol_version": "1.0",
            "rpc_id": "rpc_00000000-0000-4000-8000-000000000202",
            "service_instance_id": "svc_00000000-0000-4000-8000-000000000202",
            "service_generation": "1",
            "method": "publish_work",
            "body": request,
        }
    )

    # Frozen v1.0 remains forward-compatible by classifying the new pair as opaque. The additive
    # v1.1 union recognizes it as exact-known and excludes it from that version's opaque branch.
    validate_schema_instance("opaque-unknown-event-draft", "1.0.0", draft)
    validate_schema_instance("event-draft", "1.0.0", draft)
    validate_schema_instance("event-draft", "1.1.0", draft)
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("opaque-unknown-event-draft", "1.1.0", draft)
    validate_schema_instance("publish-work-request", "1.0.0", request)
    validate_schema_instance("publish-work-request", "1.1.0", request)
    validate_schema_instance("control-request", "2.3.0", control)
    validate_schema_instance("control-request", "2.4.0", control)
