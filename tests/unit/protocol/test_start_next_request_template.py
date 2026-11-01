"""The start authoring scaffold is closed, bound, and projection-only."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, cast

import pytest
from jsonschema import Draft7Validator, Draft202012Validator
from pydantic import ValidationError

from finishup.application.start import StartInternalResult, start_projection_wire
from finishup.mcp.descriptors import descriptor_for
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import (
    FrontierModel,
    PublishWorkRequestModel,
    StartCompactViewModel,
    StartSuccessModel,
    StartVersionSliceModel,
)
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance

_REQUEST_ID = "req_00000000-0000-4000-8000-000000000001"
_TASK_ID = "tsk_00000000-0000-4000-8000-000000000002"
_SESSION_ID = "ses_00000000-0000-4000-8000-000000000003"
_WRITER_ID = "wri_00000000-0000-4000-8000-000000000004"
_HEAD = "sha256:" + "1" * 64


def _internal() -> StartInternalResult:
    return StartInternalResult(
        protocol_version="0.1",
        schema_version="1.0.0",
        request_id=_REQUEST_ID,
        ok=True,
        outcome="created",
        task_id=_TASK_ID,
        session_id=_SESSION_ID,
        writer_id=_WRITER_ID,
        frontier=FrontierModel(sequence="1", head_digest=_HEAD),
        compact=StartCompactViewModel.model_validate(
            {
                "open_obligation_count": "0",
                "unanswered_finding_count": "0",
                "receipt_blocking_finding_count": "0",
                "ledger_freshness": "current",
                "coverage": {
                    "publication_channels": ["cooperative_mcp"],
                    "authorship_assurance": "self_asserted",
                    "artifact_observation": "published_only",
                    "evidence_immutability": "content_digest",
                    "ledger_freshness": "current",
                    "check_types": ["none"],
                    "known_gaps": [],
                },
                "gaps": [],
            }
        ),
        versions=StartVersionSliceModel(
            protocol_version="0.1",
            engine_version="0.1.0",
            projection_version="0.1.0",
            policy_packs=(),
        ),
    )


def _privacy_projection() -> dict[str, JsonValue]:
    return {
        "sink": "agent_context",
        "local_disclosure_receipt_id": "egr_00000000-0000-4000-8000-000000000005",
        "policy_id": "pvy_00000000-0000-4000-8000-000000000006",
        "policy_version": "1",
        "policy_digest": "sha256:" + "2" * 64,
        "included_categories": [],
        "blocked_categories": [],
        "omitted_pointers": [],
        "projection_commitment": "hmac-sha256:" + "3" * 64,
    }


def _public_wire() -> dict[str, JsonValue]:
    return {**start_projection_wire(_internal()), "privacy_projection": _privacy_projection()}


def test_template_is_closed_and_bound_to_the_start_result() -> None:
    internal = _internal()
    wire = _public_wire()
    result = StartSuccessModel.model_validate(wire)
    template = result.next_request_template
    arguments = template.arguments

    assert template.evidential is False
    assert template.operation == "publish_work"
    assert arguments.protocol_version == internal.protocol_version
    assert arguments.schema_version == internal.schema_version
    assert arguments.session_id == internal.session_id
    assert arguments.writer_id == internal.writer_id
    assert arguments.expected_frontier == internal.frontier
    assert tuple(draft.event_schema.name for draft in arguments.event_drafts) == (
        "plan_published",
        "obligation_published",
    )
    assert "next_request_template" not in internal.as_wire()


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("session_id", "ses_00000000-0000-4000-8000-000000000013"),
        ("writer_id", "wri_00000000-0000-4000-8000-000000000014"),
        (
            "expected_frontier",
            {"sequence": "2", "head_digest": "sha256:" + "4" * 64},
        ),
    ],
)
def test_template_rejects_tampered_result_bindings(field: str, replacement: JsonValue) -> None:
    wire = deepcopy(_public_wire())
    template = cast(dict[str, JsonValue], wire["next_request_template"])
    arguments = cast(dict[str, JsonValue], template["arguments"])
    arguments[field] = replacement

    with pytest.raises(ValidationError, match="start_next_request_binding_mismatch"):
        StartSuccessModel.model_validate(wire)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [("request_id", _REQUEST_ID), ("unexpected", True)],
)
def test_template_rejects_non_placeholder_content_and_extra_fields(
    field: str, replacement: JsonValue
) -> None:
    wire = deepcopy(_public_wire())
    template = cast(dict[str, JsonValue], wire["next_request_template"])
    arguments = cast(dict[str, JsonValue], template["arguments"])
    arguments[field] = replacement

    with pytest.raises(ValidationError):
        StartSuccessModel.model_validate(wire)


def test_frozen_schema_rejects_reversed_or_mismatched_scaffold_drafts() -> None:
    wire = _public_wire()
    validate_schema_instance("start-result", "1.0.0", wire)

    reversed_wire = deepcopy(wire)
    template = cast(dict[str, JsonValue], reversed_wire["next_request_template"])
    arguments = cast(dict[str, JsonValue], template["arguments"])
    drafts = cast(list[JsonValue], arguments["event_drafts"])
    drafts.reverse()
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("start-result", "1.0.0", reversed_wire)

    mismatched_wire = deepcopy(wire)
    template = cast(dict[str, JsonValue], mismatched_wire["next_request_template"])
    arguments = cast(dict[str, JsonValue], template["arguments"])
    draft_objects = cast(list[dict[str, JsonValue]], arguments["event_drafts"])
    schema = cast(dict[str, JsonValue], draft_objects[0]["schema"])
    schema["name"] = "obligation_published"
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("start-result", "1.0.0", mismatched_wire)


def test_mcp_output_schema_accepts_real_start_scaffold_with_legacy_and_modern_validators() -> None:
    """Cursor's legacy items semantics must accept the real two-draft start result (#153)."""

    wire = _public_wire()
    schema = cast(dict[str, Any], dict(descriptor_for("start").output_schema))

    cast(Any, Draft7Validator(schema)).validate(wire)
    cast(Any, Draft202012Validator(schema)).validate(wire)


def test_projection_is_deterministic_without_mutating_the_internal_wire() -> None:
    internal = _internal()
    legacy = internal.as_wire()

    first = start_projection_wire(internal)
    second = start_projection_wire(internal)

    assert first == second
    assert internal.as_wire() == legacy
    assert "next_request_template" not in legacy

    template = cast(dict[str, JsonValue], first["next_request_template"])
    arguments = cast(dict[str, JsonValue], template["arguments"])
    drafts = cast(list[dict[str, JsonValue]], arguments["event_drafts"])
    plan_parents = cast(list[JsonValue], drafts[0]["causal_parents"])
    obligation_parents = cast(list[JsonValue], drafts[1]["causal_parents"])
    assert plan_parents is not obligation_parents
    plan_parents.append("")
    assert obligation_parents == []


def test_filling_only_placeholders_produces_an_admissible_publish_request() -> None:
    projection = start_projection_wire(_internal())
    template = cast(dict[str, JsonValue], projection["next_request_template"])
    arguments = cast(dict[str, JsonValue], deepcopy(template["arguments"]))
    arguments["request_id"] = "req_00000000-0000-4000-8000-000000000011"
    arguments["actor"] = {"actor_id": "agent:test", "actor_type": "logical_agent"}
    arguments["client"] = {
        "kind": "cooperative_agent",
        "version": "0.1.0",
        "integration": "cooperative_mcp",
    }
    drafts = cast(list[dict[str, JsonValue]], arguments["event_drafts"])
    plan_id = "evt_00000000-0000-4000-8000-000000000012"
    obligation_id = "obl_00000000-0000-4000-8000-000000000013"
    drafts[0]["event_id"] = plan_id
    drafts[0]["occurred_at"] = "2026-08-04T12:00:00.000Z"
    plan_payload = cast(dict[str, JsonValue], drafts[0]["payload"])
    plan_payload["summary"] = "Implement and verify the bounded protocol change."
    plan_payload["obligation_refs"] = [obligation_id]
    drafts[1]["event_id"] = "evt_00000000-0000-4000-8000-000000000014"
    drafts[1]["occurred_at"] = "2026-08-04T12:00:00.000Z"
    obligation_payload = cast(dict[str, JsonValue], drafts[1]["payload"])
    obligation_payload["obligation_id"] = obligation_id
    obligation_payload["description"] = "Deliver the requested protocol change."
    obligation_payload["acceptance_criteria"] = "Focused protocol tests pass."
    obligation_payload["evidence_expectation"] = "A named focused test run."

    request = PublishWorkRequestModel.model_validate(arguments)

    assert request.session_id == _SESSION_ID
    assert request.writer_id == _WRITER_ID
    assert len(request.event_drafts) == 2
