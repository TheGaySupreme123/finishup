"""Raw MCP negotiation and exact static tool/resource inventory."""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Mapping
from typing import cast

import pytest
from mcp import types

from yoetz.mcp.descriptors import (
    CLAUDE_CODE_INSTRUCTIONS_BUDGET,
    INITIALIZE_GUIDANCE_URIS,
    TOOL_DESCRIPTORS,
    server_instructions,
)
from yoetz.mcp.resources import GUIDANCE_RESOURCES
from yoetz.mcp.resources import read_resource as read_guidance_resource
from yoetz.mcp.semantic_destination import (
    DISCLOSURE_PREFIX,
    read_semantic_destination_disclosure,
)
from yoetz.mcp.server import BRIDGE_RUNTIME, list_resources, list_tools


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _run_raw(
    *frames: Mapping[str, object],
    semantic: str = "on",
    host: str = "generic",
) -> tuple[list[dict[str, object]], bytes]:
    child = f"from yoetz.mcp.server import main; main(semantic={semantic!r}, host={host!r})"
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", child],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    responses: list[dict[str, object]] = []
    for frame in frames:
        payload = json.dumps(frame, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        process.stdin.write(payload + b"\n")
        process.stdin.flush()
        if "id" in frame:
            response = process.stdout.readline()
            assert response
            responses.append(cast(dict[str, object], json.loads(response)))
    process.stdin.close()
    assert process.wait(timeout=10) == 0
    stderr = process.stderr.read()
    assert b"Traceback" not in stderr
    return responses, stderr


def _plain_json(value: object) -> object:
    if isinstance(value, Mapping):
        source = cast(Mapping[object, object], value)
        return {str(key): _plain_json(item) for key, item in source.items()}
    if isinstance(value, tuple | list):
        source_sequence = cast(tuple[object, ...] | list[object], value)
        return [_plain_json(item) for item in source_sequence]
    return value


def _external_schema_refs(value: object) -> tuple[str, ...]:
    if isinstance(value, Mapping):
        source = cast(Mapping[object, object], value)
        found: list[str] = []
        ref = source.get("$ref")
        if isinstance(ref, str) and ref.startswith(("http://", "https://")):
            found.append(ref)
        for item in source.values():
            found.extend(_external_schema_refs(item))
        return tuple(found)
    if isinstance(value, tuple | list):
        found: list[str] = []
        sequence = cast(tuple[object, ...] | list[object], value)
        for item in sequence:
            found.extend(_external_schema_refs(item))
        return tuple(found)
    return ()


def _schema_keyword_count(value: object, keyword: str) -> int:
    if isinstance(value, Mapping):
        source = cast(Mapping[object, object], value)
        return int(keyword in source) + sum(
            _schema_keyword_count(item, keyword) for item in source.values()
        )
    if isinstance(value, tuple | list):
        sequence = cast(tuple[object, ...] | list[object], value)
        return sum(_schema_keyword_count(item, keyword) for item in sequence)
    return 0


def _initialize(protocol_version: object, request_id: int = 1) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "initialize",
        "params": {
            "protocolVersion": protocol_version,
            "capabilities": {},
            "clientInfo": {"name": "raw-contract-test", "version": "1.0.0"},
        },
    }


@pytest.mark.anyio
async def test_static_inventory_is_exact_and_verified() -> None:
    tools = await list_tools()
    resources = await list_resources()

    descriptors = TOOL_DESCRIPTORS["policy"]
    assert [tool.name for tool in tools] == [item.name for item in descriptors]
    assert len(tools) == 8
    for tool, descriptor in zip(tools, descriptors, strict=True):
        assert tool.inputSchema == _plain_json(descriptor.input_schema)
        assert tool.outputSchema is not None
        assert tool.outputSchema == _plain_json(descriptor.output_schema)
        assert tool.outputSchema["type"] == "object"
        assert "type" not in descriptor.catalog_output_schema
        assert _schema_keyword_count(tool.outputSchema, "prefixItems") == 0
        assert _external_schema_refs(tool.inputSchema) == ()
        assert _external_schema_refs(tool.outputSchema) == ()
        assert tool.annotations == types.ToolAnnotations(
            title=descriptor.title,
            readOnlyHint=descriptor.annotations.read_only,
            destructiveHint=False,
            idempotentHint=descriptor.annotations.idempotent,
            openWorldHint=descriptor.annotations.open_world,
        )
    start_descriptor = next(item for item in descriptors if item.name == "start")
    assert _schema_keyword_count(start_descriptor.catalog_output_schema, "prefixItems") == 1
    assert _schema_keyword_count(start_descriptor.output_schema, "prefixItems") == 0
    assert [str(resource.uri) for resource in resources] == [
        item.uri for item in GUIDANCE_RESOURCES
    ]
    agent = (
        read_guidance_resource("yoetz://guidance/agent-instructions.md").decode("utf-8").rstrip()
    )
    workflow = read_guidance_resource("yoetz://guidance/workflow.md").decode("utf-8").rstrip()
    coverage = (
        read_guidance_resource("yoetz://guidance/coverage-and-receipts.md").decode("utf-8").rstrip()
    )
    assert INITIALIZE_GUIDANCE_URIS == ("yoetz://guidance/agent-instructions.md",)
    assert BRIDGE_RUNTIME.instructions.startswith(agent)
    # #300: workflow.md and coverage-and-receipts.md are reached through the catalog and
    # read_guidance, not inlined here. Both URIs stay named so the agent can still find them.
    assert workflow not in BRIDGE_RUNTIME.instructions
    assert coverage not in BRIDGE_RUNTIME.instructions
    assert "yoetz://guidance/workflow.md" in BRIDGE_RUNTIME.instructions
    assert "yoetz://guidance/coverage-and-receipts.md" in BRIDGE_RUNTIME.instructions
    assert "Route profile: policy." in BRIDGE_RUNTIME.instructions
    # #479: the policy bridge names its startup-read AI-powered review destination (or states that it is
    # unknown or none); the strict route never carries the passage.
    assert DISCLOSURE_PREFIX in BRIDGE_RUNTIME.instructions
    assert DISCLOSURE_PREFIX not in server_instructions("strict")
    assert "Do not call `resources/list` or `list_mcp_resources` to find Yoetz guidance" in (
        BRIDGE_RUNTIME.instructions
    )


def test_raw_initialize_for_the_claude_host_serves_the_capped_instructions() -> None:
    # Issue #789: Claude Code desktop keeps the first 2,048 characters of this block. The
    # `--host claude` bridge therefore serves the compact Claude body instead of the packaged
    # document, with the same route tail and startup-read disclosure as every other host.
    frames, _stderr = _run_raw(
        _initialize(types.LATEST_PROTOCOL_VERSION),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        host="claude",
    )
    initialize = cast(dict[str, object], frames[0]["result"])
    instructions = cast(str, initialize["instructions"])
    assert instructions == server_instructions(
        "policy",
        host_profile="claude",
        semantic_destination=read_semantic_destination_disclosure(),
    )
    assert instructions.startswith("# Yoetz: call start first\n\n")
    assert len(instructions) <= CLAUDE_CODE_INSTRUCTIONS_BUDGET["observed_host_cap_chars"]
    assert DISCLOSURE_PREFIX in instructions
    assert "Route profile: policy." in instructions


def test_raw_initialize_lists_exact_capabilities_tools_and_resources() -> None:
    frames, _stderr = _run_raw(
        _initialize(types.LATEST_PROTOCOL_VERSION),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "resources/list", "params": {}},
    )
    by_id = {frame.get("id"): frame for frame in frames}
    initialize = cast(dict[str, object], by_id[1]["result"])
    assert initialize["protocolVersion"] == types.LATEST_PROTOCOL_VERSION
    assert initialize["capabilities"] == {
        "resources": {"subscribe": False, "listChanged": False},
        "tools": {"listChanged": False},
    }
    # #479: the child bridge renders its destination disclosure from the configuration visible
    # in the environment it was spawned with, so the expected string is rendered from that same
    # environment here rather than taken from the import-time module constant.
    instructions = cast(str, initialize["instructions"])
    assert instructions == server_instructions(
        "policy", semantic_destination=read_semantic_destination_disclosure()
    )
    assert instructions.startswith(
        BRIDGE_RUNTIME.instructions.partition("\n\nRoute profile: policy. ")[0]
    )

    tool_result = cast(dict[str, object], by_id[2]["result"])
    advertised = cast(list[dict[str, object]], tool_result["tools"])
    assert [tool["name"] for tool in advertised] == [
        item.name for item in TOOL_DESCRIPTORS["policy"]
    ]
    resource_result = cast(dict[str, object], by_id[3]["result"])
    advertised_resources = cast(list[dict[str, object]], resource_result["resources"])
    assert [resource["uri"] for resource in advertised_resources] == [
        item.uri for item in GUIDANCE_RESOURCES
    ]


def test_route_profile_is_fixed_in_initialize_and_tools_list() -> None:
    frames: tuple[dict[str, object], ...] = (
        _initialize(types.LATEST_PROTOCOL_VERSION),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    )

    policy, _ = _run_raw(*frames, semantic="on")
    strict, _ = _run_raw(*frames, semantic="off")

    for responses, profile, open_world, descriptors in (
        (policy, "policy", True, TOOL_DESCRIPTORS["policy"]),
        (strict, "strict", False, TOOL_DESCRIPTORS["strict"]),
    ):
        by_id = {frame.get("id"): frame for frame in responses}
        initialized = cast(dict[str, object], by_id[1]["result"])
        assert f"Route profile: {profile}." in cast(str, initialized["instructions"])
        listed = cast(dict[str, object], by_id[2]["result"])
        tools = cast(list[dict[str, object]], listed["tools"])
        assert [tool["name"] for tool in tools] == [descriptor.name for descriptor in descriptors]
        check = next(tool for tool in tools if tool["name"] == "check")
        annotations = cast(dict[str, object], check["annotations"])
        assert annotations["openWorldHint"] is open_world


def test_unknown_protocol_falls_back_to_latest_supported() -> None:
    frames, _stderr = _run_raw(_initialize("1900-01-01"))

    assert len(frames) == 1
    result = cast(dict[str, object], frames[0]["result"])
    assert frames[0]["id"] == 1
    assert "error" not in frames[0]
    assert result["protocolVersion"] == types.LATEST_PROTOCOL_VERSION


def test_malicious_unknown_tool_name_is_sanitized_over_stdio() -> None:
    """Unregistered tools/call names become JSON-RPC errors without echoing the raw name."""

    injected = "evil\n\x1b[31m" + ("A" * 4000) + "\nTOOL_NAME_INJECTION_MARKER"
    frames, stderr = _run_raw(
        _initialize(types.LATEST_PROTOCOL_VERSION),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": injected, "arguments": {}},
        },
    )
    by_id = {frame.get("id"): frame for frame in frames}
    initialize = cast(dict[str, object], by_id[1]["result"])
    assert initialize["protocolVersion"] == types.LATEST_PROTOCOL_VERSION

    error_frame = by_id[2]
    assert "result" not in error_frame
    error = cast(dict[str, object], error_frame["error"])
    assert error["code"] == -32602
    message = cast(str, error["message"])
    assert message == "The requested tool is not registered."
    assert injected not in message
    assert "TOOL_NAME_INJECTION_MARKER" not in message
    assert "\n" not in message

    # Stderr must not contain the raw injected name or newline-split payload fragments.
    assert b"TOOL_NAME_INJECTION_MARKER" not in stderr
    assert b"\x1b[31m" not in stderr
    # Protocol stdout stays one JSON-RPC object per response line (already parsed above).
    assert all(isinstance(frame.get("jsonrpc"), str) for frame in frames)
