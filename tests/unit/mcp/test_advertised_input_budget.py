"""Bound the actual tools/list payload before a host rewrites its schemas."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Mapping
from copy import deepcopy
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from builders.publish_identity import bridge_bound
from finishup.mcp import advertisement, descriptors
from finishup.mcp.advertisement import ADVERTISED_INPUT_SCHEMA_MAX_BYTES, compact_input_schema
from finishup.mcp.descriptors import TOOL_DESCRIPTORS, McpRouteProfile, descriptor_for
from finishup.mcp.resources import read_resource
from finishup.mcp.server import build_bridge_runtime, call_tool, list_tools
from finishup.ports.control import McpHostProfile
from finishup.protocol.models import PublishWorkRequest
from finishup.protocol.schemas import load_schema_catalog


@pytest.mark.parametrize(
    "operation", ("start", "check", "receipt", "closure_prepare", "read_guidance")
)
def test_descriptions_survive_when_the_projected_tool_fits(operation: str) -> None:
    descriptor = descriptor_for(operation)
    full = cast(dict[str, Any], descriptor.input_schema["properties"])
    advertised = cast(dict[str, Any], descriptor.advertised_input_schema["properties"])
    for field, body in full.items():
        if "description" in body:
            assert advertised[field]["description"] == body["description"]


def test_oversized_tool_keeps_priority_descriptions_greedily() -> None:
    full = cast(dict[str, Any], deepcopy(dict(descriptor_for("check").input_schema)))
    # This fits by itself but competes with the operational rules; traversal alone would
    # consume their budget on actor context first.
    full["properties"]["actor"]["description"] = "Low priority context. " * 70
    projected = compact_input_schema("check", full)
    fields = cast(dict[str, Any], projected["properties"])
    for field in ("await_observations", "final_review", "mode", "expected_frontier"):
        assert fields[field]["description"] == full["properties"][field]["description"]
    assert "description" not in fields["actor"]
    assert len(json.dumps(dict(projected), separators=(",", ":")).encode()) <= 4_800


def test_respond_keeps_disposition_and_finding_frontier_rules() -> None:
    descriptor = descriptor_for("respond")
    full = cast(dict[str, Any], descriptor.input_schema["properties"])
    fields = cast(dict[str, Any], descriptor.advertised_input_schema["properties"])
    for field in ("disposition", "finding_frontier", "duplicate_of_finding_id"):
        assert fields[field]["description"] == full[field]["description"]
    # #1162: the advisory answers fit beside those rules; how to target an advisory is in the
    # never-trimmed tool description rather than in the budgeted field descriptions.
    assert {"addressed", "declined"} <= set(fields["disposition"]["enum"])
    assert "Addressed (reason, evidence_refs)" in fields["disposition"]["description"]
    assert "check-event-id:ordinal in finding_id" in descriptor.description


@pytest.mark.parametrize("host", ("codex", "claude", "cursor"))
def test_over_budget_bridge_starts_with_minimal_schema_and_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
    host: McpHostProfile,
) -> None:
    diagnostics: list[dict[str, Any]] = []

    def record_diagnostic(**kwargs: Any) -> None:
        diagnostics.append(kwargs)

    monkeypatch.setattr(advertisement, "ADVERTISED_INPUT_SCHEMA_MAX_BYTES", 1)
    monkeypatch.setattr(
        advertisement,
        "record_bounded_event_without_raising",
        record_diagnostic,
    )
    clear_cache = getattr(descriptors, "_advertised_input_schema").cache_clear
    clear_cache()
    try:
        tools = asyncio.run(list_tools(build_bridge_runtime(host_profile=host)))
        assert len(tools) == len(TOOL_DESCRIPTORS["policy"])
        assert len(diagnostics) == len(tools)
        assert all(
            item["reason"] == "mcp_advertised_input_schema_over_budget" for item in diagnostics
        )
        for tool in tools:
            assert "description" not in tool.inputSchema
            Draft202012Validator.check_schema(tool.inputSchema)
            # The existing CI budget assertion must still reject this runtime fallback.
            assert (
                len(json.dumps(tool.inputSchema).encode())
                > advertisement.ADVERTISED_INPUT_SCHEMA_MAX_BYTES
            )
    finally:
        clear_cache()


def _assert_hint_accepts_catalog_shape(
    hint: dict[str, Any], source: Mapping[str, Any], definitions: Mapping[str, Any]
) -> None:
    assert set(hint) <= {"type", "enum", "items"}
    while "$ref" in source:
        source = definitions[source["$ref"].removeprefix("#/$defs/")]
    if "type" in hint:
        assert source.get("type") == hint["type"]
    if "enum" in hint:
        assert "enum" in source
        assert set(source["enum"]) <= set(hint["enum"])
    if "items" in hint:
        _assert_hint_accepts_catalog_shape(hint["items"], source["items"], definitions)


def test_payload_hints_accept_every_ordinary_family_and_version() -> None:
    descriptor = descriptor_for("publish_work")
    items = cast(dict[str, Any], descriptor.input_schema["properties"])["event_drafts"]["items"]
    allowed = {
        (
            branch["properties"]["schema"]["properties"]["name"]["const"].replace("_", "-"),
            branch["properties"]["schema"]["properties"]["version"]["const"],
        )
        for branch in items["oneOf"]
    }
    hints = cast(dict[str, Any], descriptor.advertised_input_schema["properties"])["event_drafts"][
        "items"
    ]["properties"]["payload"]["properties"]
    checked: set[tuple[str, str]] = set()
    for document in load_schema_catalog().documents:
        key = (document.schema_name, document.schema_version)
        if key not in allowed:
            continue
        checked.add(key)
        for field, source in cast(dict[str, Any], document.json_schema["properties"]).items():
            if field not in hints:
                continue
            _assert_hint_accepts_catalog_shape(
                hints[field], source, cast(Mapping[str, Any], document.json_schema.get("$defs", {}))
            )
    assert checked == allowed


@pytest.mark.parametrize("profile", ("policy", "strict"))
def test_worked_examples_validate_full_repair_graph(profile: McpRouteProfile) -> None:
    for descriptor in TOOL_DESCRIPTORS[profile]:
        validator = cast(Any, Draft202012Validator(cast(Any, descriptor.input_schema)))
        for example in cast(list[dict[str, Any]], descriptor.input_schema.get("examples", [])):
            validator.validate(example)


@pytest.mark.parametrize("profile", ("policy", "strict"))
def test_tools_list_input_schema_fits_below_codex_compaction(profile: McpRouteProfile) -> None:
    runtime = build_bridge_runtime(route_profile=profile)
    for tool in asyncio.run(list_tools(runtime)):
        encoded = json.dumps(tool.inputSchema, separators=(",", ":")).encode("utf-8")
        assert len(encoded) <= ADVERTISED_INPUT_SCHEMA_MAX_BYTES == 4_800, (
            profile,
            tool.name,
            len(encoded),
        )
        Draft202012Validator.check_schema(tool.inputSchema)
        assert '"$ref"' not in encoded.decode()
        full = descriptor_for(tool.name, profile).input_schema
        assert tool.inputSchema["required"] == full["required"]
        assert (
            tool.inputSchema["properties"].keys() == cast(dict[str, Any], full["properties"]).keys()
        )


def test_all_worked_examples_fit_advertised_and_full_catalog_schemas() -> None:
    for descriptor in TOOL_DESCRIPTORS["policy"]:
        advertised = cast(Any, Draft202012Validator(cast(Any, descriptor.advertised_input_schema)))
        full = cast(Any, Draft202012Validator(cast(Any, descriptor.catalog_input_schema)))
        for example in cast(list[dict[str, Any]], descriptor.input_schema.get("examples", [])):
            advertised.validate(example)
            full.validate(example)


def test_guidance_request_templates_fit_advertised_and_full_catalog_schemas() -> None:
    text = read_resource("finishup://guidance/request-templates.md").decode()
    operations: set[str] = set()
    for block in re.findall(r"```json\n(.*?)\n```", text, re.DOTALL):
        request = cast(dict[str, Any], json.loads(block))
        operation = next(
            name
            for field, name in (
                ("uri", "read_guidance"),
                ("selection", "closure_prepare"),
                ("event_drafts", "publish_work"),
                ("finding_id", "respond"),
                ("task_id", "receipt"),
                ("view", "status"),
                ("expected_frontier", "check"),
                ("mode", "start"),
            )
            if field in request
        )
        descriptor = descriptor_for(operation)
        cast(Any, Draft202012Validator(cast(Any, descriptor.advertised_input_schema))).validate(
            request
        )
        cast(Any, Draft202012Validator(cast(Any, descriptor.catalog_input_schema))).validate(
            request
        )
        cast(Any, Draft202012Validator(cast(Any, descriptor.input_schema))).validate(request)
        operations.add(operation)
    assert operations == {item.name for item in TOOL_DESCRIPTORS["policy"]}


def test_publish_examples_remain_strictly_validated_after_advertisement() -> None:
    descriptor = descriptor_for("publish_work")
    examples = cast(list[dict[str, Any]], descriptor.input_schema["examples"])
    for example in examples:
        PublishWorkRequest.model_validate(bridge_bound(example))
    invalid = deepcopy(examples[0])
    invalid["event_drafts"][0]["payload"]["invented_payload_field"] = True
    # Advertisement intentionally accepts an open payload; actual dispatch must not use it.
    cast(Any, Draft202012Validator(cast(Any, descriptor.advertised_input_schema))).validate(invalid)
    with pytest.raises(ValidationError):
        PublishWorkRequest.model_validate(bridge_bound(invalid))
    validator = cast(Any, Draft202012Validator(cast(Any, descriptor.catalog_input_schema)))
    assert not validator.is_valid(invalid)
    invalid["dry_run"] = True  # No operation-recovery lookup or service access is needed.
    result = asyncio.run(call_tool("publish_work", invalid, build_bridge_runtime()))
    assert result.isError
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "INVALID_REQUEST"


@pytest.mark.parametrize("operation", ("check", "status", "respond"))
def test_permissive_authoring_constraints_do_not_weaken_dispatch(operation: str) -> None:
    descriptor = descriptor_for(operation)
    request = deepcopy(cast(list[dict[str, Any]], descriptor.input_schema["examples"])[0])
    if operation == "check":
        request["expected_frontier"] = {"sequence": "1", "head_digest": "genesis"}
    elif operation == "status":
        request["view"] = "history"
        request["filter"] = {"after_sequence": "9223372036854775808"}
    else:
        request["disposition"] = "self_verified"
        request.pop("evidence_refs", None)
        request.pop("reason", None)
    cast(Any, Draft202012Validator(cast(Any, descriptor.advertised_input_schema))).validate(request)
    assert not cast(Any, Draft202012Validator(cast(Any, descriptor.catalog_input_schema))).is_valid(
        request
    )
    result = asyncio.run(call_tool(operation, request, build_bridge_runtime()))
    assert result.isError
    assert result.structuredContent is not None
    assert result.structuredContent["error"]["code"] == "INVALID_REQUEST"


def test_listing_does_not_change_output_schemas() -> None:
    tools = asyncio.run(list_tools(build_bridge_runtime()))
    for tool, descriptor in zip(tools, TOOL_DESCRIPTORS["policy"], strict=True):
        assert tool.outputSchema == dict(descriptor.output_schema)
