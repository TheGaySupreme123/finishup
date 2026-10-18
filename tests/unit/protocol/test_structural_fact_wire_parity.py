"""Every closed structural fact the hook emits crosses the control wire (#1039).

tb4n4 D: 439 ``control_frame_invalid`` rejections in 31 of 60 attempts. ADR-045 taught the hook
two more ``write_scope`` values (``notes`` and ``workspace``, a shell command that writes the
workspace) and raised its commitment bound from 32 to 80, while the control-request 2.9.0 wire
still admitted three scopes and 32 commitments. The client validates a frame before sending it, so
the shell write that should make an earlier check stale was refused on every drain pass and
quarantined after 128 consecutive refusals, never reaching the ledger.

These tests read each value from the emitter's own closed set, not a copy, and send it the way the
hook drain does: the domain request serializer, the client's frame encoder (which validates
against the packaged wire schema), and the service's frame parser.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from typing import Any, cast

import pytest

from finishup.domain.command_segments import MAX_COMMAND_COMMITMENTS
from finishup.domain.observation import (
    _RUNNER_CLASSES,
    _RUNTIME_FACT_VALUES,
    ObservationIngestRequest,
    observation_ingest_request_from_json,
    observation_ingest_request_to_json,
)
from finishup.domain.values import JsonObject, freeze_json
from finishup.domain.write_scope import WRITE_SCOPES
from finishup.ports.control import ControlCallRequest, ControlMethod
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.schemas import schema_document_for
from finishup.service.control_protocol import (
    ControlProtocolError,
    decode_control_frame,
    encode_control_frame,
    parse_control_request,
)

_INSTANCE_ID = "svc_00000000-0000-4000-8000-000000000001"
_RPC_ID = "rpc_00000000-0000-4000-8000-000000000002"


def _commitment(seed: int) -> str:
    return f"hmac-sha256:{seed:064x}"


def _shell_write_post(**overrides: Any) -> dict[str, Any]:
    """The issue's row: a Claude Code ``Bash`` post whose command wrote a workspace file.

    The keys and values are the ones the real hook emits for ``printf x > solve.py``; only the
    keyed commitments are fixed placeholders.
    """

    structural: dict[str, Any] = {
        "action": "claude_tool_success",
        "capability_profile_id": "claude-code-ordinary-observation-v1",
        "command_commitment": _commitment(1),
        "command_composition": "single",
        "command_segment_commitments": [_commitment(2)],
        "correlation_kind": "tool_call_id",
        "effective_user": "non_root",
        "event_ordinal": 2,
        "hook_name": "PostToolUse",
        "mapping_hint": "claude-code-hooks-ordinary-v2",
        "pairing_mode": "paired",
        "result_status": "success",
        "runner_class": "other",
        "success": True,
        "tool_call_id": "toolu-1039",
        "tool_name": "Bash",
        "write_scope": "workspace",
    }
    structural.update(overrides)
    return {
        "codex_session_id": "claude:session-1039",
        "envelope": {
            "content_object_refs": [],
            "cursor": {
                "byte_position": 0,
                "event_position": 2,
                "last_source_commitment": _commitment(3),
                "mapping_version": "codex-obs-hook/1.0.0",
                "source_generation": 1,
            },
            "event_kind": "PostToolUse",
            "gap_codes": ["content_unselected"],
            "receipt_time": "2026-10-12T00:00:00.000Z",
            "session_commitment": _commitment(4),
            "source": "claude_hook",
            "source_identity": "hook:native",
            "structural_payload": structural,
        },
    }


def _frame(body: JsonObject) -> bytes:
    """Encode one ingest call as the client does: the packaged wire schema validates it."""

    return encode_control_frame(
        ControlCallRequest(
            kind="call",
            protocol_version="1.0",
            rpc_id=_RPC_ID,
            service_instance_id=_INSTANCE_ID,
            service_generation="1",
            method=ControlMethod.OBSERVATION_INGEST,
            body=body,
        )
    )


def _send(body: dict[str, Any]) -> ObservationIngestRequest:
    """Serialize as the hook does, encode as the client does, parse as the service does."""

    request = observation_ingest_request_from_json(freeze_json(body))
    parsed = parse_control_request(
        decode_control_frame(_frame(observation_ingest_request_to_json(request)))
    )
    assert isinstance(parsed, ControlCallRequest)
    assert parsed.method is ControlMethod.OBSERVATION_INGEST
    received = observation_ingest_request_from_json(cast(JsonObject, parsed.body))
    assert received == request
    return received


def _wire_structural_fields() -> dict[str, Any]:
    document = cast(dict[str, Any], schema_document_for("control-request", "2.9.0").json_schema)
    envelope = document["$defs"]["observation_envelope"]["oneOf"][0]
    return envelope["properties"]["structural_payload"]["properties"]


def test_the_wire_admits_exactly_the_write_scopes_the_hook_emits() -> None:
    assert set(_wire_structural_fields()["write_scope"]["enum"]) == set(WRITE_SCOPES)


@pytest.mark.parametrize("scope", sorted(WRITE_SCOPES))
def test_every_write_scope_crosses_the_control_wire(scope: str) -> None:
    received = _send(_shell_write_post(write_scope=scope))
    assert received.envelope.structural_payload["write_scope"] == scope


@pytest.mark.parametrize(
    ("key", "value"),
    sorted(
        [
            (key, value)
            for key, values in _RUNTIME_FACT_VALUES.items()
            if key != "write_scope"
            for value in values
        ]
        + [("runner_class", value) for value in _RUNNER_CLASSES]
    ),
)
def test_every_other_closed_runtime_fact_crosses_the_control_wire(key: str, value: str) -> None:
    """The same parity for every other closed token the hook classifies, so the next value added
    on one side only fails here instead of in a recorded run."""

    body = _shell_write_post(**{key: value})
    # Only the fact under test varies; a plain command carries no write scope.
    del body["envelope"]["structural_payload"]["write_scope"]
    received = _send(body)
    assert received.envelope.structural_payload[key] == value


def test_the_wire_admits_the_hook_commitment_bound() -> None:
    """ADR-045 carries 32 segment and 48 canonical commitments in one list: a long compiler or
    simulator command must still cross (the hook emits 37 for ``cd /app && iverilog -g2012 -Wall
    -o sim`` with 21 sources ``&& vvp sim``, which the old bound of 32 refused)."""

    assert _wire_structural_fields()["command_segment_commitments"]["maxItems"] == (
        MAX_COMMAND_COMMITMENTS
    )
    commitments = [_commitment(100 + index) for index in range(MAX_COMMAND_COMMITMENTS)]
    received = _send(_shell_write_post(command_segment_commitments=commitments))
    carried = cast(
        tuple[str, ...], received.envelope.structural_payload["command_segment_commitments"]
    )
    assert len(carried) == MAX_COMMAND_COMMITMENTS


def test_the_wire_stays_closed_to_a_class_the_hook_never_emits() -> None:
    """``deliverable`` is decided in the kernel from the declared outputs; it never crosses."""

    _frame(cast(JsonObject, freeze_json(_shell_write_post())))
    refused = cast(JsonObject, freeze_json(_shell_write_post(write_scope="deliverable")))
    with pytest.raises(ControlProtocolError, match="frame_invalid"):
        _frame(refused)
    # The domain refuses it first, so the hook can never build such a row.
    with pytest.raises(ProtocolValueError):
        observation_ingest_request_from_json(refused)


def test_the_wire_admits_exactly_the_workspace_effects_the_hook_emits() -> None:
    """PR #1080: the before/after fingerprint token crosses unchanged, and nothing else does."""

    from finishup.domain.workspace_effect import WORKSPACE_EFFECTS

    assert set(_wire_structural_fields()["workspace_effect"]["enum"]) == set(WORKSPACE_EFFECTS)
    for effect in sorted(WORKSPACE_EFFECTS):
        received = _send(_shell_write_post(workspace_effect=effect))
        assert received.envelope.structural_payload["workspace_effect"] == effect
    refused = cast(JsonObject, freeze_json(_shell_write_post(workspace_effect="read_only")))
    with pytest.raises(ControlProtocolError, match="frame_invalid"):
        _frame(refused)
    with pytest.raises(ProtocolValueError):
        observation_ingest_request_from_json(refused)


def test_an_edited_write_scope_enum_cannot_reach_an_older_service() -> None:
    """n7 RC2 (#1106): ``docs`` was added to the unreleased 2.9.0 enum in place. A new hook can
    never send it to an older running service, whose enum would refuse it (the #1039 shape):
    the schema manifest pins the 2.9.0 bytes, both handshake sides compare the whole manifest
    digest before any request frame, and a peer built from other bytes is refused as
    ``manifest_mismatch`` (the hook keeps its rows for the superseding service; an MCP bridge or
    ``finishup service restart`` supersedes the stale holder through its lock stamp)."""

    import hashlib
    import json

    from finishup.protocol.schemas import _read_resource, _schema_root, schema_manifest_digest

    root = _schema_root()
    manifest = json.loads(_read_resource(root.joinpath("manifest.json"), "missing"))
    member = next(
        item
        for item in manifest["members"]
        if item["path"] == "service/control-request-2.9.0.schema.json"
    )
    body = _read_resource(root.joinpath(member["path"]), "missing")
    assert member["sha256"] == "sha256:" + hashlib.sha256(body).hexdigest()
    assert "docs" in _wire_structural_fields()["write_scope"]["enum"]
    manifest_bytes = _read_resource(root.joinpath("manifest.json"), "missing")
    assert schema_manifest_digest() == "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
