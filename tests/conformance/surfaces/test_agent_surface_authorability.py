"""Regression tests for the degraded MCP schema lowering observed at the Codex boundary."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

import pytest

from yoetz.mcp.descriptors import (
    ORDINARY_MCP_PUBLISH_EVENT_FAMILIES,
    TOOL_DESCRIPTORS,
    McpRouteProfile,
    descriptor_for,
)
from yoetz.mcp.resources import GUIDANCE_RESOURCES
from yoetz.protocol.canonical import JsonValue
from yoetz.protocol.models import (
    CheckRequestModel,
    ClosurePrepareRequestModel,
    PublishWorkRequestModel,
    ReadGuidanceRequestModel,
    ReceiptRequestModel,
    RespondRequestModel,
    StartRequestModel,
    StatusRequestModel,
)

_UNKNOWN = "unknown"
_ENVELOPE_FIELDS = {
    "event_id",
    "schema",
    "occurred_at",
    "causal_parents",
    "payload",
    "artifact_refs",
    "evidence_refs",
}
_DROPPED_METADATA_KEYS = frozenset({"$defs", "enum", "examples", "oneOf"})
_JSON_FENCE_RE = re.compile(r"```json\n(?P<body>.*?)\n```", re.DOTALL)
_REQUEST_TEMPLATE_URI = "yoetz://guidance/request-templates.md"
_OBSERVATION_FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "fixtures"
    / "codex-tool-boundary"
    / "codex-testing-0.147.0-alpha.1.observation.json"
)


def _lower_observed_host_shape(schema: Mapping[str, JsonValue]) -> dict[str, Any] | str:
    """Lower only host-stable inline shapes; local refs and conditionals are unsupported."""

    if "$ref" in schema or any(key in schema for key in ("allOf", "if", "then", "else")):
        return _UNKNOWN

    const = schema.get("const")
    if const is not None:
        return {"kind": "literal", "values": (const,)}
    enum = schema.get("enum")
    if isinstance(enum, list):
        return {"kind": "enum", "values": tuple(cast(list[JsonValue], enum))}

    schema_type = schema.get("type")
    if schema_type == "object":
        properties = schema.get("properties", {})
        if not isinstance(properties, Mapping):
            return _UNKNOWN
        typed_properties = cast(Mapping[str, JsonValue], properties)
        return {
            "kind": "object",
            "properties": {
                name: _lower_observed_host_shape(cast(Mapping[str, JsonValue], child))
                if isinstance(child, Mapping)
                else _UNKNOWN
                for name, child in typed_properties.items()
            },
        }
    if schema_type == "array":
        items = schema.get("items")
        return {
            "kind": "array",
            "items": _lower_observed_host_shape(cast(Mapping[str, JsonValue], items))
            if isinstance(items, Mapping)
            else _UNKNOWN,
        }
    if isinstance(schema_type, str):
        return {"kind": schema_type}

    for union_keyword in ("oneOf", "anyOf"):
        branches = schema.get(union_keyword)
        if isinstance(branches, list):
            typed_branches = cast(list[JsonValue], branches)
            lowered = tuple(
                _lower_observed_host_shape(cast(Mapping[str, JsonValue], branch))
                if isinstance(branch, Mapping)
                else _UNKNOWN
                for branch in typed_branches
            )
            if not lowered or all(branch == _UNKNOWN for branch in lowered):
                return _UNKNOWN
            return {"kind": "union", "options": lowered}
    return _UNKNOWN


@pytest.mark.parametrize("profile", tuple(TOOL_DESCRIPTORS))
def test_required_tool_arguments_remain_authorable_under_observed_lowering(profile: str) -> None:
    route_profile = cast(McpRouteProfile, profile)
    for descriptor in TOOL_DESCRIPTORS[route_profile]:
        schema = descriptor.input_schema
        lowered = _lower_observed_host_shape(schema)
        assert lowered != _UNKNOWN, (profile, descriptor.name)
        assert isinstance(lowered, dict) and lowered["kind"] == "object"
        lowered_properties = cast(dict[str, object], lowered["properties"])
        required = schema.get("required")
        assert isinstance(required, list)
        required_names = [name for name in cast(list[JsonValue], required) if type(name) is str]
        assert len(required_names) == len(required)
        unknown_required = [name for name in required_names if lowered_properties[name] == _UNKNOWN]
        assert unknown_required == [], (profile, descriptor.name, unknown_required)


@pytest.mark.parametrize("profile", tuple(TOOL_DESCRIPTORS))
def test_publish_work_envelope_remains_authorable_under_observed_lowering(profile: str) -> None:
    route_profile = cast(McpRouteProfile, profile)
    lowered = _lower_observed_host_shape(descriptor_for("publish_work", route_profile).input_schema)
    assert isinstance(lowered, dict)
    event_drafts = cast(dict[str, Any], lowered["properties"])["event_drafts"]
    assert event_drafts["kind"] == "array"
    envelope = event_drafts["items"]
    assert envelope != _UNKNOWN
    assert envelope["kind"] == "object"
    assert set(envelope["properties"]) == _ENVELOPE_FIELDS

    schema_shape = envelope["properties"]["schema"]
    assert schema_shape["kind"] == "object"
    family_shape = schema_shape["properties"]["name"]
    assert family_shape == {
        "kind": "enum",
        "values": tuple(sorted(ORDINARY_MCP_PUBLISH_EVENT_FAMILIES)),
    }
    assert envelope["properties"]["payload"] == {"kind": "object", "properties": {}}


@pytest.mark.parametrize("profile", tuple(TOOL_DESCRIPTORS))
def test_check_scope_and_start_root_remain_objects_under_observed_lowering(profile: str) -> None:
    route_profile = cast(McpRouteProfile, profile)
    start = _lower_observed_host_shape(descriptor_for("start", route_profile).input_schema)
    assert isinstance(start, dict) and start["kind"] == "object"

    check = _lower_observed_host_shape(descriptor_for("check", route_profile).input_schema)
    assert isinstance(check, dict) and check["kind"] == "object"
    scope = cast(dict[str, Any], check["properties"])["scope"]
    assert scope["kind"] == "object"
    assert set(scope["properties"]) == {"claim_ids", "obligation_ids"}


def _drop_host_metadata(value: JsonValue) -> JsonValue:
    """Model a host that preserves structure/text but drops rich schema metadata."""

    if isinstance(value, Mapping):
        return {
            key: _drop_host_metadata(child)
            for key, child in cast(Mapping[str, JsonValue], value).items()
            if key not in _DROPPED_METADATA_KEYS
        }
    if isinstance(value, list):
        return [_drop_host_metadata(child) for child in cast(list[JsonValue], value)]
    return value


def _degraded_agent_surface(profile: McpRouteProfile) -> str:
    """Return only the tool identity text, metadata-poor schemas, and guidance bytes."""

    tools = [
        {
            "name": descriptor.name,
            "title": descriptor.title,
            "description": descriptor.description,
            "input_schema": _drop_host_metadata(descriptor.input_schema),
        }
        for descriptor in TOOL_DESCRIPTORS[profile]
    ]
    resources = "\n".join(resource.text for resource in GUIDANCE_RESOURCES)
    return json.dumps(tools, ensure_ascii=False, sort_keys=True) + "\n" + resources


def _request_model_and_operation(
    request: Mapping[str, JsonValue],
) -> tuple[type[Any], str]:
    if "uri" in request:
        return ReadGuidanceRequestModel, "read_guidance"
    if {"session_id", "writer_id", "selection"} <= request.keys():
        return ClosurePrepareRequestModel, "closure_prepare"
    if "event_drafts" in request:
        return PublishWorkRequestModel, "publish_work"
    if "finding_id" in request:
        return RespondRequestModel, "respond"
    if "task_id" in request:
        return ReceiptRequestModel, "receipt"
    if "view" in request:
        return StatusRequestModel, "status"
    if "expected_frontier" in request:
        return CheckRequestModel, "check"
    return StartRequestModel, "start"


@pytest.mark.parametrize("profile", tuple(TOOL_DESCRIPTORS))
def test_degraded_surface_templates_remain_authorable(profile: str) -> None:
    route_profile = cast(McpRouteProfile, profile)
    surface = _degraded_agent_surface(route_profile)
    template_resource = next(
        resource for resource in GUIDANCE_RESOURCES if resource.uri == _REQUEST_TEMPLATE_URI
    )
    template_text = template_resource.text

    # The fallback must survive even when the host removes the metadata that carried the original
    # examples and event-family discriminators.
    stripped_schema = _drop_host_metadata(
        descriptor_for("publish_work", route_profile).input_schema
    )
    serialized_schema = json.dumps(stripped_schema, sort_keys=True)
    for dropped in _DROPPED_METADATA_KEYS:
        assert f'"{dropped}"' not in serialized_schema

    raw_blocks = [match.group("body") for match in _JSON_FENCE_RE.finditer(template_text)]
    assert raw_blocks
    parsed_requests = [cast(Mapping[str, JsonValue], json.loads(block)) for block in raw_blocks]
    operations: set[str] = set()
    families: set[str] = set()
    check_scopes: set[str] = set()

    for block, request in zip(raw_blocks, parsed_requests, strict=True):
        model, operation = _request_model_and_operation(request)
        model.model_validate(request)
        operations.add(operation)
        assert "src/" not in block
        assert "schemas/" not in block
        assert block in surface

        if operation == "publish_work":
            drafts = cast(list[JsonValue], request["event_drafts"])
            for draft in drafts:
                draft_map = cast(Mapping[str, JsonValue], draft)
                schema = cast(Mapping[str, JsonValue], draft_map["schema"])
                families.add(cast(str, schema["name"]))
        elif operation == "check":
            check_scopes.add("scoped" if "scope" in request else "whole")

    assert operations == {
        "start",
        "publish_work",
        "status",
        "check",
        "respond",
        "receipt",
        "closure_prepare",
        "read_guidance",
    }
    assert families == ORDINARY_MCP_PUBLISH_EVENT_FAMILIES
    assert check_scopes == {"whole", "scoped"}


def test_recorded_codex_consumer_observation_is_bounded_and_honest() -> None:
    observation = cast(dict[str, Any], json.loads(_OBSERVATION_FIXTURE.read_bytes()))

    assert observation["record_schema"] == "yoetz.codex-tool-boundary-observation/1.0.0"
    assert observation["classification"] == "observation_record"
    assert observation["consumer"]["version"] == "0.147.0-alpha.1"
    assert "does not run or certify Codex" in observation["ci_claim"]

    baseline = observation["baseline"]
    assert baseline["producer_commit"] == "959f20c36b0d50b21a482b85035adbe5fc8848d4"
    assert len(baseline["model_visible_declaration"]) == 7
    assert baseline["operations"] == {"attempted": 17, "rejected": 9}

    post_fix = observation["post_fix"]
    assert post_fix["producer_commit"] == "23ff890835c53ba1e015e20f1b56aaad0f8fd5d7"
    raw = post_fix["raw_inventory"]
    assert raw["tool_count"] == 6
    assert raw["start_root_type"] == "object"
    assert raw["publish_event_drafts_items_type"] == "object"
    assert set(raw["publish_envelope_fields"]) == _ENVELOPE_FIELDS
    # This is evidence for the frozen 0.2 producer, not a native-host execution of the later
    # multi-agent surface. New families are proven separately by current authorability tests.
    assert set(raw["publish_schema_name_families"]) == {
        "action_recorded",
        "assignment_recorded",
        "claim_recorded",
        "decision_recorded",
        "evidence_recorded",
        "obligation_published",
        "plan_published",
        "plan_revised",
        "result_recorded",
    }
    assert raw["request_id_type"] == "string"
    assert raw["check_expected_frontier_type"] == "object"
    assert raw["check_scope_type"] == "object"
    assert post_fix["fresh_model_visible_probe"]["status"] == "unavailable"
