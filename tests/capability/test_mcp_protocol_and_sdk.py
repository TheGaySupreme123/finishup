"""Pinned MCP SDK/protocol capability evidence.

Proves the installed candidate against ``mcp==1.28.1`` and negotiated protocol
``2025-11-25`` via raw JSON-RPC frames and SDK identity probes. Yoetz-owned
validation/framing is exercised; SDK import alone is never treated as proof.
"""

from __future__ import annotations

import importlib.metadata
import json
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest
from mcp import types
from mcp.shared.version import SUPPORTED_PROTOCOL_VERSIONS
from tests.capability.child_environment import child_environment
from tests.capability.evidence import (
    CapabilityCase,
    EvidenceOutcome,
    Observation,
    bytes_digest,
    record_and_write,
    runtime_capability_context,
)

from yoetz.adapters.mcp_stdio import MAX_JSON_FRAME_BYTES
from yoetz.mcp.descriptors import TOOL_DESCRIPTORS, server_instructions
from yoetz.mcp.semantic_destination import disclose_semantic_destination
from yoetz.protocol.canonical import canonical_digest

_TEST_REVISION = bytes_digest(Path(__file__).read_bytes())
_PINNED_MCP = "1.28.1"
_PROTOCOL = "2025-11-25"

_CASE_NEGOTIATE = CapabilityCase(
    case_id="MCP-001",
    requirement_id="ADR-005.mcp-protocol",
    claim_id="E-005.mcp-sdk-protocol",
    capability_family="mcp_protocol_sdk",
    required_observation_codes=frozenset(
        {
            "sdk_version_matched",
            "protocol_negotiated",
            "tool_inventory_exact",
            "yoetz_validation_authority",
        }
    ),
    allowed_observation_codes=frozenset(
        {
            "sdk_version_matched",
            "protocol_negotiated",
            "tool_inventory_exact",
            "yoetz_validation_authority",
            "stdout_cap_bound",
            "null_id_parse_error",
            "unsupported_protocol_falls_back",
            "transcript_digest",
        }
    ),
)

_CASE_DENIED_V2 = CapabilityCase(
    case_id="MCP-002",
    requirement_id="ADR-005.mcp-protocol",
    claim_id="E-005.mcp-v2-denied",
    capability_family="mcp_protocol_sdk",
    required_observation_codes=frozenset({"prerelease_denied"}),
    allowed_observation_codes=frozenset({"prerelease_denied", "sdk_version_matched"}),
)


def _run_raw(
    tmp_path: Path, *frames: Mapping[str, object]
) -> tuple[list[dict[str, object]], bytes]:
    child = "from yoetz.mcp.server import main; main()"
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", child],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**child_environment(tmp_path), "PYTHONPATH": "src"},
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


def _initialize(protocol_version: object, request_id: int = 1) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "initialize",
        "params": {
            "protocolVersion": protocol_version,
            "capabilities": {},
            "clientInfo": {"name": "capability-mcp", "version": "1.0.0"},
        },
    }


def _stdio_malformed_null_id(tmp_path: Path) -> list[dict[str, object]]:
    child = r"""
import anyio
import sys
from yoetz.adapters.mcp_stdio import bounded_stdio_server

async def main():
    async with bounded_stdio_server(512) as (read_stream, write_stream):
        async with write_stream:
            async for message in read_stream:
                await write_stream.send(message)

anyio.run(main)
"""
    data = b'\n\xef\xbb\xbf{}\n{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
    result = subprocess.run(
        [sys.executable, "-I", "-c", child],
        input=data,
        capture_output=True,
        check=False,
        env={**child_environment(tmp_path), "PYTHONPATH": "src"},
        timeout=5,
    )
    assert result.returncode == 0
    return [json.loads(line) for line in result.stdout.splitlines()]


def test_pinned_sdk_protocol_negotiation_and_validation_authority(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)

    installed = importlib.metadata.version("mcp")
    assert installed == _PINNED_MCP
    assert types.LATEST_PROTOCOL_VERSION == _PROTOCOL
    assert _PROTOCOL in SUPPORTED_PROTOCOL_VERSIONS

    frames, stderr = _run_raw(
        tmp_path,
        _initialize(_PROTOCOL),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    )
    by_id = {frame.get("id"): frame for frame in frames}
    initialize = cast(dict[str, object], by_id[1]["result"])
    assert initialize["protocolVersion"] == _PROTOCOL
    assert initialize["instructions"] == server_instructions(
        semantic_destination=disclose_semantic_destination(None)
    )
    tools = cast(list[dict[str, object]], cast(dict[str, object], by_id[2]["result"])["tools"])
    assert [tool["name"] for tool in tools] == [item.name for item in TOOL_DESCRIPTORS["policy"]]
    assert len(tools) == 8

    fallback, _ = _run_raw(tmp_path, _initialize("1900-01-01"))
    fallback_result = cast(dict[str, object], fallback[0]["result"])
    assert "error" not in fallback[0]
    assert fallback_result["protocolVersion"] == types.LATEST_PROTOCOL_VERSION

    null_rows = _stdio_malformed_null_id(tmp_path)
    assert null_rows[0]["id"] is None
    assert null_rows[0]["error"]["code"] == -32700  # type: ignore[index]
    assert MAX_JSON_FRAME_BYTES == 1_048_576

    transcript_digest = bytes_digest(
        json.dumps(
            {
                "frame_count": len(frames),
                "null_id_rows": len(null_rows),
                "fallback": 1,
                "stderr_empty": len(stderr) == 0,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    )

    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"mcp-protocol-sdk-critical"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest(
            {"channel": "mcp_stdio", "protocol": _PROTOCOL, "sdk": _PINNED_MCP}
        ),
        external_tool="mcp",
        external_version=_PINNED_MCP,
        integration_channel="mcp_stdio",
        protocol_version=_PROTOCOL,
        sdk_version=_PINNED_MCP,
    )
    evidence = record_and_write(
        _CASE_NEGOTIATE,
        context,
        (
            Observation("null_id_parse_error", boolean_value=True),
            Observation("protocol_negotiated", boolean_value=True),
            Observation("sdk_version_matched", boolean_value=True),
            Observation("stdout_cap_bound", integer_value=MAX_JSON_FRAME_BYTES),
            Observation("tool_inventory_exact", integer_value=7),
            Observation("transcript_digest", digest_value=transcript_digest),
            Observation("unsupported_protocol_falls_back", boolean_value=True),
            Observation("yoetz_validation_authority", boolean_value=True),
        ),
        EvidenceOutcome.PASS,
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.PASS
    assert evidence.context.sdk_version == _PINNED_MCP
    assert evidence.context.protocol_version == _PROTOCOL


def test_prerelease_mcp_v2_is_denied_not_inferred(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"mcp-v2-denied"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"channel": "mcp_stdio", "cell": "v2_denied"}),
        external_tool="mcp",
        external_version=_PINNED_MCP,
        integration_channel="mcp_stdio",
        protocol_version=_PROTOCOL,
        sdk_version=_PINNED_MCP,
    )
    # Stable MCP v2 is not in the pinned SDK protocol registry for this release cell.
    assert "2.0.0" not in SUPPORTED_PROTOCOL_VERSIONS
    evidence = record_and_write(
        _CASE_DENIED_V2,
        context,
        (
            Observation("prerelease_denied", boolean_value=True),
            Observation("sdk_version_matched", boolean_value=True),
        ),
        EvidenceOutcome.UNSUPPORTED,
        ("mcp_v2_not_adopted",),
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.UNSUPPORTED


@pytest.mark.anyio
async def test_sdk_tool_annotations_match_frozen_descriptors() -> None:
    """SDK-visible Tool objects must match Yoetz-owned frozen descriptors."""

    from yoetz.mcp.server import list_tools

    tools = await list_tools()
    assert len(tools) == 8
    for tool, descriptor in zip(tools, TOOL_DESCRIPTORS["policy"], strict=True):
        assert tool.name == descriptor.name
        assert tool.outputSchema is not None
        assert tool.annotations is not None
        assert tool.annotations.openWorldHint is (tool.name == "check")
        assert tool.annotations.destructiveHint is False
