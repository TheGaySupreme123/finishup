"""Root-level object rules must name safe corrective fields.

Replays the second failed `start` from the 2026-07-27 dogfood: `workspace_ref` without
`external_ref` previously collapsed to a generic invalid-arguments message because
`dependentRequired` reports an empty instance path. Nested enum/pattern pointers and hostile
extras must keep their existing bounded behavior.
"""

from __future__ import annotations

from copy import deepcopy
from typing import cast

import pytest
from pydantic import ValidationError

from builders.publish_identity import bridge_bound
from finishup.mcp.descriptors import descriptor_for
from finishup.mcp.errors import authoring_hint, safe_validation_locations
from finishup.mcp.server import invalid_request_message
from finishup.protocol.models import PublishWorkRequest, StartRequestModel

_START_SCHEMA = descriptor_for("start").input_schema
_PUBLISH_SCHEMA = descriptor_for("publish_work").input_schema

_BASE_START: dict[str, object] = {
    "protocol_version": "0.1",
    "schema_version": "1.0.0",
    "request_id": "req_00000000-0000-4000-8000-000000000001",
    "mode": "create",
    "task_title": "dogfood start",
    "requested_view": "compact",
    "actor": {"actor_id": "agent:logical-1", "actor_type": "logical_agent"},
    "client": {
        "kind": "cooperative_agent",
        "version": "0.1.0",
        "integration": "cooperative_mcp",
    },
}


def _start_locations(**overrides: object) -> tuple[dict[str, str], ...]:
    payload = {**_BASE_START, **overrides}
    with pytest.raises(ValidationError) as captured:
        StartRequestModel.model_validate(payload)
    return safe_validation_locations(captured.value)


def test_workspace_ref_without_external_ref_names_both_fields_and_pairing_rule() -> None:
    locations = _start_locations(workspace_ref="workspace-A")
    assert {"field": "/workspace_ref", "reason": "paired_field_required"} in locations
    assert {"field": "/external_ref", "reason": "paired_field_required"} in locations

    hint = authoring_hint(_START_SCHEMA, locations)
    assert "workspace_ref requires external_ref" in hint
    message = invalid_request_message("start", locations)
    assert "workspace_ref requires external_ref" in message
    assert "finishup://guidance/request-templates.md" in message


def test_external_ref_without_workspace_ref_is_equally_actionable() -> None:
    locations = _start_locations(external_ref="external-A")
    assert {"field": "/external_ref", "reason": "paired_field_required"} in locations
    assert {"field": "/workspace_ref", "reason": "paired_field_required"} in locations
    hint = authoring_hint(_START_SCHEMA, locations)
    assert "external_ref requires workspace_ref" in hint


def test_logical_agent_without_refs_remains_valid() -> None:
    # The dogfood's third-call actor_type change was a red herring; logical_agent is admitted.
    StartRequestModel.model_validate(_BASE_START)


def test_paired_refs_together_remain_valid() -> None:
    StartRequestModel.model_validate(
        {**_BASE_START, "external_ref": "external-A", "workspace_ref": "workspace-A"}
    )


def test_attach_if_then_names_safe_required_alternatives() -> None:
    locations = _start_locations(mode="attach")
    fields = {item["field"] for item in locations}
    reasons = {item["reason"] for item in locations}
    assert "/session_id" in fields
    assert "/external_ref" in fields
    assert "/workspace_ref" in fields
    assert reasons == {"conditional_field_required"}

    hint = authoring_hint(_START_SCHEMA, locations)
    assert "mode attach requires" in hint
    assert "session_id" in hint
    assert "external_ref" in hint
    assert "workspace_ref" in hint


def test_nested_request_id_pattern_retains_existing_behavior() -> None:
    locations = _start_locations(request_id="not-a-valid-request-id")
    assert any(item["field"] == "/request_id" for item in locations)
    hint = authoring_hint(_START_SCHEMA, locations)
    assert "^req_" in hint


def test_nested_event_draft_enum_retains_existing_behavior() -> None:
    examples = cast(list[object], _PUBLISH_SCHEMA["examples"])
    base = cast(dict[str, object], examples[0])
    good = cast(dict[str, object], cast(list[object], base["event_drafts"])[0])
    secret = "NOT-A-REAL-ENUM-never-echo-this"
    bad: dict[str, object] = {
        **good,
        "event_id": "evt_00000000-0000-4000-8000-000000000099",
        "schema": {"name": "action_recorded", "version": "1.0.0"},
        "payload": {
            "action_id": "act_00000000-0000-4000-8000-000000000098",
            "action_kind": secret,
            "description": "x",
        },
    }
    with pytest.raises(ValidationError) as captured:
        PublishWorkRequest.model_validate(bridge_bound({**base, "event_drafts": [good, bad]}))
    locations = safe_validation_locations(captured.value)
    assert any(item["field"] == "/event_drafts/1/payload/action_kind" for item in locations)
    assert secret not in repr(locations)
    hint = authoring_hint(_PUBLISH_SCHEMA, locations)
    assert "action_kind admits" in hint
    assert secret not in hint


def test_selected_payload_one_of_names_its_missing_co_required_field() -> None:
    """A satisfied strength discriminator must not be re-reported as an enum failure (#306)."""

    base = deepcopy(cast(dict[str, object], cast(list[object], _PUBLISH_SCHEMA["examples"])[0]))
    draft = cast(dict[str, object], cast(list[object], base["event_drafts"])[0])
    draft["schema"] = {"name": "evidence_recorded", "version": "1.1.0"}
    draft["payload"] = {
        "evidence_id": "evd_00000000-0000-4000-8000-000000000001",
        "evidence_kind": "artifact",
        "strength": "mutable_reference",
        "observed_at": "2026-01-01T00:00:00.000Z",
        "description": "bounded evidence description",
    }
    with pytest.raises(ValidationError) as captured:
        PublishWorkRequest.model_validate(bridge_bound(base))

    locations = safe_validation_locations(captured.value)
    assert locations == (
        {
            "field": "/event_drafts/0/payload/reference",
            "reason": "conditional_field_required",
            "family": "evidence_recorded",
            "family_version": "1.1.0",
            "condition_field": "strength",
            "condition_value": "mutable_reference",
        },
    )
    message = invalid_request_message("publish_work", locations)
    assert "strength mutable_reference requires reference" in message
    assert "strength admits" not in message


def test_selected_payload_any_of_required_names_metadata_only_alternatives() -> None:
    """A metadata_only draft missing both description and reference must name the pair (#335)."""

    base = deepcopy(cast(dict[str, object], cast(list[object], _PUBLISH_SCHEMA["examples"])[0]))
    draft = cast(dict[str, object], cast(list[object], base["event_drafts"])[0])
    draft["schema"] = {"name": "evidence_recorded", "version": "1.1.0"}
    draft["payload"] = {
        "evidence_id": "evd_00000000-0000-4000-8000-000000000001",
        "evidence_kind": "artifact",
        "strength": "metadata_only",
        "observed_at": "2026-01-01T00:00:00.000Z",
    }
    with pytest.raises(ValidationError) as captured:
        PublishWorkRequest.model_validate(bridge_bound(base))

    locations = safe_validation_locations(captured.value)
    assert locations == (
        {
            "field": "/event_drafts/0/payload/description",
            "reason": "conditional_field_required",
            "family": "evidence_recorded",
            "family_version": "1.1.0",
            "condition_field": "strength",
            "condition_value": "metadata_only",
        },
        {
            "field": "/event_drafts/0/payload/reference",
            "reason": "conditional_field_required",
            "family": "evidence_recorded",
            "family_version": "1.1.0",
            "condition_field": "strength",
            "condition_value": "metadata_only",
        },
    )
    message = invalid_request_message("publish_work", locations)
    assert "strength metadata_only requires description or reference" in message
    assert "each event_drafts entry requires" not in message
    assert "strength admits" not in message


def test_selected_payload_required_peers_share_one_complete_hint_part() -> None:
    """One selected branch's peers must not consume the global three-part hint budget."""

    base = deepcopy(cast(dict[str, object], cast(list[object], _PUBLISH_SCHEMA["examples"])[0]))
    draft = cast(dict[str, object], cast(list[object], base["event_drafts"])[0])
    draft["schema"] = {"name": "evidence_recorded", "version": "1.1.0"}
    draft["payload"] = {
        "evidence_id": "evd_00000000-0000-4000-8000-000000000001",
        "evidence_kind": "artifact",
        "strength": "independently_reproduced",
        "observed_at": "2026-01-01T00:00:00.000Z",
        "description": "bounded evidence description",
    }
    with pytest.raises(ValidationError) as captured:
        PublishWorkRequest.model_validate(bridge_bound(base))

    locations = safe_validation_locations(captured.value)
    message = invalid_request_message("publish_work", locations)
    assert message.count("strength independently_reproduced requires") == 1
    assert "captured_object_id, content_digest, and subject_state" in message


def test_selected_payload_all_of_requires_digest_binding_with_content_digest() -> None:
    """A content_digest draft missing digest_binding must name the allOf peer (#335)."""

    base = deepcopy(cast(dict[str, object], cast(list[object], _PUBLISH_SCHEMA["examples"])[0]))
    draft = cast(dict[str, object], cast(list[object], base["event_drafts"])[0])
    draft["schema"] = {"name": "evidence_recorded", "version": "1.1.0"}
    draft["payload"] = {
        "evidence_id": "evd_00000000-0000-4000-8000-000000000001",
        "evidence_kind": "artifact",
        "strength": "content_digest",
        "content_digest": "sha256:" + ("0" * 64),
        "observed_at": "2026-01-01T00:00:00.000Z",
        "description": "bounded evidence description",
    }
    with pytest.raises(ValidationError) as captured:
        PublishWorkRequest.model_validate(bridge_bound(base))

    locations = safe_validation_locations(captured.value)
    assert locations == (
        {
            "field": "/event_drafts/0/payload/digest_binding",
            "reason": "conditional_field_required",
            "family": "evidence_recorded",
            "family_version": "1.1.0",
        },
    )
    message = invalid_request_message("publish_work", locations)
    assert "content_digest requires digest_binding" in message
    assert "each event_drafts entry requires" not in message
    assert "strength admits" not in message


def _action_recorded_locations(payload: dict[str, object]) -> tuple[dict[str, str], ...]:
    base = deepcopy(cast(dict[str, object], cast(list[object], _PUBLISH_SCHEMA["examples"])[0]))
    draft = cast(dict[str, object], cast(list[object], base["event_drafts"])[0])
    draft["schema"] = {"name": "action_recorded", "version": "1.0.0"}
    draft["payload"] = payload
    with pytest.raises(ValidationError) as captured:
        PublishWorkRequest.model_validate(bridge_bound(base))
    return safe_validation_locations(captured.value)


def test_unconditional_payload_required_is_not_reported_as_conditional() -> None:
    """A plain missing payload field must keep an actionable envelope hint, not a bare pointer.

    Without a discriminator to select the branch, a top-level ``required`` failure carries no
    activating condition, so no repair sentence can be rendered for it. Projecting it as
    ``conditional_field_required`` therefore both mislabelled the rule and produced an empty hint.
    """

    locations = _action_recorded_locations(
        {"action_kind": "edit", "description": "bounded action description"}
    )
    assert all(item.get("reason") != "conditional_field_required" for item in locations)
    # The selected family rides along for the hint builder only; it never reaches the wire.
    assert locations == (
        {
            "field": "/event_drafts/0/payload",
            "reason": "invalid_type_or_value",
            "family": "action_recorded",
            "family_version": "1.0.0",
            # Schema-listed required names the draft lacks, also hint-only (tb4n1).
            "missing_fields": "action_id",
        },
    )

    # The selected family's own contract names the missing key; the envelope recital, which the
    # well-formed draft already satisfies, is no longer the answer (benchmark full3).
    hint = authoring_hint(_PUBLISH_SCHEMA, locations)
    assert (
        "the action_recorded 1.0.0 payload is missing action_id; it requires action_id, "
        "action_kind, and description"
    ) in hint
    message = invalid_request_message("publish_work", locations)
    assert "payload is missing action_id; it requires action_id" in message
    assert "each event_drafts entry requires" not in message


def test_selected_payload_all_of_property_const_names_its_required_peer() -> None:
    """A command action missing ``command`` must name the const condition that activated it."""

    locations = _action_recorded_locations(
        {
            "action_id": "act_00000000-0000-4000-8000-000000000001",
            "action_kind": "command",
            "description": "bounded action description",
        }
    )
    assert locations == (
        {
            "field": "/event_drafts/0/payload/command",
            "reason": "conditional_field_required",
            "family": "action_recorded",
            "family_version": "1.0.0",
        },
    )
    message = invalid_request_message("publish_work", locations)
    assert "action_kind command requires command" in message
    assert "action_kind admits" not in message


def test_mixed_payload_requireds_report_only_the_conditional_peer() -> None:
    """An unconditional miss beside a conditional one must not borrow the conditional token."""

    locations = _action_recorded_locations(
        {"action_kind": "command", "description": "bounded action description"}
    )
    assert all(item.get("field") != "/event_drafts/0/payload/action_id" for item in locations)
    assert locations == (
        {
            "field": "/event_drafts/0/payload/command",
            "reason": "conditional_field_required",
            "family": "action_recorded",
            "family_version": "1.0.0",
        },
    )
    assert "action_kind command requires command" in authoring_hint(_PUBLISH_SCHEMA, locations)


def test_unselected_sibling_branch_contract_is_never_projected() -> None:
    """When const rejections cannot isolate one branch, no branch's contract is projected.

    An extra key on the draft ``schema`` object leaves two live branches, so selection fails.
    The projection must then degrade to the generic rule instead of recursing into a
    discriminator-rejected sibling and misattributing its family version.
    """

    base = deepcopy(cast(dict[str, object], cast(list[object], _PUBLISH_SCHEMA["examples"])[0]))
    draft = cast(dict[str, object], cast(list[object], base["event_drafts"])[0])
    draft["schema"] = {"name": "evidence_recorded", "version": "1.1.0", "extra": "x"}
    draft["payload"] = {
        "evidence_id": "evd_00000000-0000-4000-8000-000000000001",
        "evidence_kind": "artifact",
        "strength": "mutable_reference",
        "observed_at": "2026-01-01T00:00:00.000Z",
        "description": "bounded evidence description",
    }
    with pytest.raises(ValidationError) as captured:
        PublishWorkRequest.model_validate(bridge_bound(base))

    locations = safe_validation_locations(captured.value)
    assert all(item.get("reason") != "conditional_field_required" for item in locations)
    assert all(item.get("family_version") != "1.0.0" for item in locations)


def test_hostile_unknown_property_never_reaches_message_or_details() -> None:
    secret_key = "hostile_secret_prop"
    secret_value = "never-echo-this-value-9f3a"
    with pytest.raises(ValidationError) as captured:
        StartRequestModel.model_validate({**_BASE_START, secret_key: secret_value})
    locations = safe_validation_locations(captured.value)
    assert secret_key not in repr(locations)
    assert secret_value not in repr(locations)
    message = invalid_request_message("start", locations)
    assert secret_key not in message
    assert secret_value not in message
    # Unrecognized extras at the model boundary stay generic — no invented field pointers.
    assert not any(secret_key in item.get("field", "") for item in locations)


def test_unrecognized_root_rule_degrades_to_bounded_generic_error() -> None:
    # Empty locations still produce a bounded public message (template + guidance), never raise.
    message = invalid_request_message("start", ())
    assert message.startswith("The tool arguments are invalid.")
    assert "finishup://guidance/request-templates.md" in message
    assert authoring_hint(_START_SCHEMA, ()) != ""


def test_object_rule_hint_never_echoes_submitted_values() -> None:
    secret = "submitted-workspace-value-must-not-leak"
    locations = _start_locations(workspace_ref=secret)
    hint = authoring_hint(_START_SCHEMA, locations)
    message = invalid_request_message("start", locations)
    assert secret not in hint
    assert secret not in message
    assert secret not in repr(locations)
