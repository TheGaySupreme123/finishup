"""Six-operation plus support-tool MCP/Codex capability evidence.

Local cells drive the six workflow names through the real MCP stdio transport (``yoetz mcp serve``
via the pinned SDK client), and verify the complete advertised inventory including read-only
support tools. They prove dispatch and descriptor behavior only — not service conduit or Codex
model activation.

Driving the same slice through interactive/exec Codex requires ``YOETZ_LIVE_CODEX=1`` and a Gate
2/3 live driver. When live authorization is present but no driver exists, the cell fails closed
with ``live_driver_unavailable`` rather than claiming a pass.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest
from mcp import ClientSession, types
from mcp.client.stdio import StdioServerParameters, stdio_client
from tests.capability.child_environment import child_environment
from tests.capability.evidence import (
    CapabilityCase,
    EvidenceOutcome,
    Observation,
    bytes_digest,
    capability_evidence_output_root,
    live_codex_authorized,
    record_and_write,
    runtime_capability_context,
)

from yoetz.mcp.descriptors import TOOL_DESCRIPTOR_SET_DIGEST, TOOL_DESCRIPTORS
from yoetz.protocol.canonical import JsonValue, canonical_digest
from yoetz.protocol.errors import PublicErrorCode

_TEST_REVISION = bytes_digest(Path(__file__).read_bytes())
_VERSION = "0.139.0"
_WORKFLOW_TOOLS = ("start", "publish_work", "check", "respond", "status", "receipt")
_EXPECTED = (*_WORKFLOW_TOOLS, "read_guidance", "closure_prepare")
_DEGRADED_CODES = frozenset(
    {
        PublicErrorCode.INVALID_REQUEST.value,
        PublicErrorCode.SERVICE_UNAVAILABLE.value,
        PublicErrorCode.VAULT_LOCKED.value,
    }
)
# The only code a rejected-but-hinted call may carry. An unreachable recovery oracle adds a
# durability caveat to this answer; it never replaces it with an uncertain one (issue #239).
_REJECTION_CODES = frozenset({PublicErrorCode.INVALID_REQUEST.value})


def _serve_parameters(tmp_path: Path) -> StdioServerParameters:
    candidate_python = os.environ.get("YOETZ_CANDIDATE_PYTHON", "").strip()
    environment = child_environment(tmp_path)
    if candidate_python:
        return StdioServerParameters(
            command=candidate_python,
            args=["-m", "yoetz", "mcp", "serve"],
            env=environment,
        )
    return StdioServerParameters(
        command="uv",
        args=["run", "yoetz", "mcp", "serve"],
        env=environment,
    )


def _id(kind: str, seed: int) -> str:
    prefixes = {
        "request": "req_",
        "task": "tsk_",
        "session": "ses_",
        "writer": "wri_",
        "finding": "fnd_",
        "event": "evt_",
    }
    return f"{prefixes[kind]}00000000-0000-4000-8000-{seed:012d}"


def _base(seed: int) -> dict[str, JsonValue]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": _id("request", seed),
        "actor": {"actor_id": "harness:six-tools", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
    }


def _schema_valid_tool_arguments() -> dict[str, dict[str, JsonValue]]:
    frontier: dict[str, JsonValue] = {"sequence": "0", "head_digest": "genesis"}
    identity: dict[str, JsonValue] = {
        "session_id": _id("session", 1),
        "writer_id": _id("writer", 1),
    }
    return {
        "start": {
            **_base(1),
            "mode": "create",
            "task_title": "Six-tools MCP conduit",
            "requested_view": "compact",
        },
        "publish_work": {
            **_base(2),
            **identity,
            "expected_frontier": frontier,
            "event_drafts": [
                {
                    "event_id": _id("event", 2),
                    "schema": {"name": "plan_published", "version": "1.0.0"},
                    "occurred_at": "2026-01-01T00:00:00.000Z",
                    "causal_parents": [],
                    "payload": {"plan_version": 1, "summary": "Plan", "obligation_refs": []},
                    "artifact_refs": [],
                    "evidence_refs": [],
                }
            ],
        },
        "check": {
            **_base(3),
            **identity,
            "expected_frontier": frontier,
            "mode": "deterministic_only",
        },
        "respond": {
            **_base(4),
            **identity,
            "expected_frontier": frontier,
            "finding_id": _id("finding", 4),
            "finding_frontier": frontier,
            "disposition": "acknowledged",
        },
        "status": {**_base(5), **identity, "view": "compact", "limit": "10"},
        "receipt": {
            **_base(6),
            **identity,
            "task_id": _id("task", 6),
            "expected_frontier": frontier,
            "format": "json",
            "include": "summary",
            "redaction_profile": "default_local_export",
        },
    }


def _plain_json(value: object) -> object:
    if isinstance(value, Mapping):
        source = cast(Mapping[object, object], value)
        return {str(key): _plain_json(item) for key, item in source.items()}
    if isinstance(value, tuple | list):
        source_sequence = cast(tuple[object, ...] | list[object], value)
        return [_plain_json(item) for item in source_sequence]
    return value


def _assert_dispatch_result(result: types.CallToolResult) -> None:
    assert result.structuredContent is not None
    structured = cast(dict[str, object], result.structuredContent)
    assert "request_id" in structured
    if result.isError:
        error = cast(dict[str, object], structured["error"])
        assert error["code"] in _DEGRADED_CODES
        assert structured.get("ok") is False
    else:
        assert structured.get("ok") is True


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_installed_server_advertises_the_frozen_mcp_inventory(tmp_path: Path) -> None:
    """List tools through the real MCP stdio server; compare against frozen descriptors."""

    evidence_root = capability_evidence_output_root(tmp_path)
    params = _serve_parameters(tmp_path)
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            listed = await session.list_tools()
    names = tuple(tool.name for tool in listed.tools)
    assert names == _EXPECTED
    descriptors = TOOL_DESCRIPTORS["policy"]
    descriptor_set_digest = TOOL_DESCRIPTOR_SET_DIGEST["policy"]
    assert tuple(item.name for item in descriptors) == _EXPECTED
    for tool, descriptor in zip(listed.tools, descriptors, strict=True):
        assert tool.inputSchema == _plain_json(descriptor.input_schema)
        assert tool.outputSchema == _plain_json(descriptor.output_schema)
    context = runtime_capability_context(
        fixture_digest=bytes_digest(descriptor_set_digest.encode("ascii")),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"descriptor_set": descriptor_set_digest}),
        external_tool="codex",
        external_version=_VERSION,
        integration_channel="codex_mcp_stdio",
        protocol_version="2025-11-25",
    )
    evidence = record_and_write(
        CapabilityCase(
            case_id="SIX-001",
            requirement_id="ADR-005.six-tools",
            claim_id="E-002.six-tools",
            capability_family="codex_six_tools",
            required_observation_codes=frozenset(
                {"tool_count", "descriptor_set_digest", "names_match"}
            ),
            allowed_observation_codes=frozenset(
                {"tool_count", "descriptor_set_digest", "names_match"}
            ),
        ),
        context,
        (
            Observation("descriptor_set_digest", digest_value=descriptor_set_digest),
            Observation("names_match", boolean_value=True),
            Observation("tool_count", integer_value=len(names)),
        ),
        EvidenceOutcome.PASS,
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.PASS


@pytest.mark.anyio
async def test_mcp_stdio_six_tool_dispatch_without_claiming_codex_activation(
    tmp_path: Path,
) -> None:
    """Drive all six names through real MCP stdio and their structured validation boundary.

    This observation is MCP dispatch coverage only. It does not call Application methods directly,
    prove service conduit behavior, or claim Codex model activation.
    """

    evidence_root = capability_evidence_output_root(tmp_path)
    arguments = _schema_valid_tool_arguments()
    params = _serve_parameters(tmp_path)
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            listed = await session.list_tools()
            assert tuple(tool.name for tool in listed.tools) == _EXPECTED
            for name in _WORKFLOW_TOOLS:
                result = await session.call_tool(
                    name,
                    {"request_id": arguments[name]["request_id"]},
                )
                _assert_dispatch_result(result)

    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"mcp-stdio-six-tools-dispatch"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"profile": "mcp_stdio_dispatch"}),
        external_tool="mcp",
        external_version="1.28.1",
        integration_channel="mcp_stdio",
        protocol_version="2025-11-25",
        sdk_version="1.28.1",
    )
    evidence = record_and_write(
        CapabilityCase(
            case_id="SIX-002",
            requirement_id="ADR-005.six-tools",
            claim_id="E-002.six-tools-mcp-stdio-dispatch",
            capability_family="codex_six_tools",
            required_observation_codes=frozenset(
                {"mcp_stdio_dispatch", "six_tools_called", "structured_result_shape"}
            ),
            allowed_observation_codes=frozenset(
                {"mcp_stdio_dispatch", "six_tools_called", "structured_result_shape"}
            ),
        ),
        context,
        (
            Observation("mcp_stdio_dispatch", boolean_value=True),
            Observation("six_tools_called", integer_value=6),
            Observation("structured_result_shape", boolean_value=True),
        ),
        EvidenceOutcome.PASS,
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.PASS


def _rejected_tool_arguments() -> dict[str, tuple[str, dict[str, JsonValue]]]:
    """Four rejections real dogfood sessions produced, in their own shapes.

    `envelope` puts the family value on a guessed top-level key (2026-08-03); `payload_key` sends
    a key the family does not admit (2026-08-13, issue #240); `scope` sends half a scope;
    `misplaced_field` puts `attempted_items` on the claim payload (2026-08-14, issue #266). All
    four were rejected safely before, and all four left the agent with nothing to author from.
    """

    valid = _schema_valid_tool_arguments()
    publish = dict(valid["publish_work"])
    drafts = cast(list[JsonValue], publish["event_drafts"])
    draft = dict(cast(Mapping[str, JsonValue], drafts[0]))
    schema = cast(Mapping[str, JsonValue], draft.pop("schema"))
    draft["event_type"] = schema["name"]
    publish["event_drafts"] = [draft]
    unknown_key_draft = dict(cast(Mapping[str, JsonValue], drafts[0]))
    payload = dict(cast(Mapping[str, JsonValue], unknown_key_draft["payload"]))
    payload["zzz_unknown"] = "x"
    unknown_key_draft["payload"] = payload
    # Declared dry run: the preview cannot append, so it must not pay for the recovery lookup.
    unknown_key_publish: dict[str, JsonValue] = {
        **valid["publish_work"],
        "event_drafts": [cast(JsonValue, unknown_key_draft)],
        "dry_run": True,
    }
    check: dict[str, JsonValue] = {
        **valid["check"],
        "scope": cast(JsonValue, {"obligation_ids": []}),
    }
    misplaced_draft = dict(cast(Mapping[str, JsonValue], drafts[0]))
    misplaced_draft["schema"] = cast(JsonValue, {"name": "claim_recorded", "version": "1.0.0"})
    misplaced_draft["payload"] = cast(
        JsonValue,
        {
            "claim_id": "clm_00000000-0000-4000-8000-000000000001",
            "claim_kind": "completion",
            "statement": "Requested work is complete.",
            "supporting_refs": ["evd_00000000-0000-4000-8000-000000000001"],
            "attempted_items": ["pytest -q"],
        },
    )
    misplaced_publish: dict[str, JsonValue] = {
        **valid["publish_work"],
        "event_drafts": [cast(JsonValue, misplaced_draft)],
        "dry_run": True,
    }
    return {
        "envelope": ("publish_work", publish),
        "payload_key": ("publish_work", unknown_key_publish),
        "scope": ("check", check),
        "misplaced_field": ("publish_work", misplaced_publish),
    }


@pytest.mark.anyio
async def test_rejected_arguments_carry_corrective_text_over_the_wire(tmp_path: Path) -> None:
    """Corrective text that never leaves the process repairs nothing.

    The dogfood host degraded the tool schema, so the error message and the guidance resources were
    the only surfaces that reached the agent. These three calls assert the repair information
    arrives over real MCP stdio rather than only in a unit-level hint.
    """

    evidence_root = capability_evidence_output_root(tmp_path)
    arguments = _rejected_tool_arguments()
    messages: dict[str, str] = {}
    details_by_label: dict[str, dict[str, object]] = {}
    text_by_label: dict[str, str] = {}
    params = _serve_parameters(tmp_path)
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            for label, (name, payload) in arguments.items():
                result = await session.call_tool(name, cast(dict[str, object], payload))
                assert result.isError is True
                assert result.structuredContent is not None
                structured = cast(dict[str, object], result.structuredContent)
                error = cast(dict[str, object], structured["error"])
                # A locally decidable rejection stays a rejection even when no service can be
                # reached: the durability caveat rides beside it, never in place of it (#239).
                assert error["code"] in _REJECTION_CODES
                messages[label] = cast(str, error["message"])
                details_by_label[label] = cast(dict[str, object], error.get("safe_details") or {})
                first_content = result.content[0]
                text_by_label[label] = cast(str, getattr(first_content, "text", ""))

    # The draft envelope: which key carries the family, and what else the envelope must carry.
    assert "schema.name admits" in messages["envelope"]
    assert "each event_drafts entry requires" in messages["envelope"]
    for key in ("event_id", "occurred_at", "causal_parents", "artifact_refs", "evidence_refs"):
        assert key in messages["envelope"]
    # The unknown payload key: the class of the mistake, and the keys the family does admit.
    assert "does not admit" in messages["payload_key"]
    assert "plan_published" in messages["payload_key"]
    for key in ("plan_version", "summary", "obligation_refs"):
        assert key in messages["payload_key"]
    assert "zzz_unknown" not in messages["payload_key"]
    assert "each event_drafts entry requires" not in messages["payload_key"]
    # Check scope: the missing peer and the omit-the-whole-object alternative.
    assert "claim_ids" in messages["scope"]
    assert "omit scope for the whole case" in messages["scope"]
    # The misplaced known field: strict rejection retained, and the one legal owning family named
    # in the message, in the structured repair fact, and on the compatible text channel (#266).
    assert "does not admit" in messages["misplaced_field"]
    assert (
        "attempted_items is admitted only by the action_recorded payload"
        in messages["misplaced_field"]
    )
    misplaced_details = details_by_label["misplaced_field"]
    assert misplaced_details["repair_kind"] == "field_ownership"
    assert misplaced_details["repair_field"] == "attempted_items"
    assert misplaced_details["repair_selected_family"] == "claim_recorded"
    assert misplaced_details["repair_owning_family"] == "action_recorded"
    assert misplaced_details["repair_template_uri"] == "yoetz://guidance/request-templates.md"
    assert (
        "Repair: attempted_items is admitted only by the action_recorded payload"
        in text_by_label["misplaced_field"]
    )

    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"mcp-stdio-corrective-authoring"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"profile": "mcp_stdio_corrective"}),
        external_tool="mcp",
        external_version="1.28.1",
        integration_channel="mcp_stdio",
        protocol_version="2025-11-25",
        sdk_version="1.28.1",
    )
    evidence = record_and_write(
        CapabilityCase(
            case_id="SIX-003",
            requirement_id="ADR-005.six-tools",
            claim_id="E-002.six-tools-corrective-authoring",
            capability_family="codex_six_tools",
            required_observation_codes=frozenset(
                {"corrective_messages_observed", "rejected_calls", "invalid_request_code"}
            ),
            allowed_observation_codes=frozenset(
                {"corrective_messages_observed", "rejected_calls", "invalid_request_code"}
            ),
        ),
        context,
        (
            Observation("corrective_messages_observed", boolean_value=True),
            Observation("invalid_request_code", boolean_value=True),
            Observation("rejected_calls", integer_value=len(messages)),
        ),
        EvidenceOutcome.PASS,
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.PASS


@pytest.mark.live
def test_live_codex_drives_six_tools(tmp_path: Path) -> None:
    """Live Codex six-tools driver is Gate 2/3 work; fail closed when unauthorized or unavailable."""

    evidence_root = capability_evidence_output_root(tmp_path)
    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"live-six-tools"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest({"cell": "live_six_tools"}),
        external_tool="codex",
        external_version=_VERSION,
        integration_channel="codex_mcp_stdio",
        protocol_version="2025-11-25",
    )
    case = CapabilityCase(
        case_id="SIX-LIVE-001",
        requirement_id="ADR-005.six-tools",
        claim_id="E-002.six-tools-live",
        capability_family="codex_six_tools",
        required_observation_codes=frozenset({"live_authorized"}),
        allowed_observation_codes=frozenset({"live_authorized", "live_driver_state"}),
    )
    if not live_codex_authorized():
        evidence = record_and_write(
            case,
            context,
            (Observation("live_authorized", boolean_value=False),),
            EvidenceOutcome.UNSUPPORTED,
            ("live_codex_not_authorized",),
            output_root=evidence_root,
        )
        assert evidence.outcome is EvidenceOutcome.UNSUPPORTED
        return
    # Authorized, but a real Codex interactive/exec driver is Gate 2/3 work and is not present.
    evidence = record_and_write(
        case,
        context,
        (
            Observation("live_authorized", boolean_value=True),
            Observation("live_driver_state", enum_value="live_driver_unavailable"),
        ),
        EvidenceOutcome.UNSUPPORTED,
        ("live_driver_unavailable",),
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.UNSUPPORTED
    pytest.skip("live_driver_unavailable: Gate 2/3 Codex driver not implemented")
