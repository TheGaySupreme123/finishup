"""Wire-level coverage for the additive 2.5 native observation handoff."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, cast

import pytest

from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.schemas import validate_schema_instance
from finishup.service.control_protocol import decode_control_frame, encode_control_frame

_INSTANCE_ID = "svc_00000000-0000-4000-8000-000000000001"
_RPC_ID = "rpc_00000000-0000-4000-8000-000000000002"
_COMMITMENT = "hmac-sha256:" + "1" * 64


def _native_frame(
    *,
    source: str = "claude_hook",
    profile: str | None = "claude-code-ordinary-observation-v1",
    mapping: str = "claude-code-hooks-ordinary-v2",
    include_capture_marker: bool = True,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "codex_session_id": "claude:control-schema-250",
        "envelope": {
            "content_object_refs": [],
            "cursor": {
                "byte_position": 0,
                "event_position": 1,
                "last_source_commitment": _COMMITMENT,
                "mapping_version": mapping,
                "source_generation": 1,
            },
            "event_kind": "PostToolUse",
            "gap_codes": [],
            "receipt_time": "2026-09-06T12:00:00.000Z",
            "session_commitment": _COMMITMENT,
            "source": source,
            "source_identity": "hook:control-schema-250",
            "structural_payload": {"tool_name": "Bash"},
        },
        "content_chunks": [
            {
                "content_kind": "tool_input",
                "correlation_identity": "hook:control-schema-250:tool-input",
                "source_commitment": _COMMITMENT,
                "media_type": "text/plain",
                "part_index": 0,
                "part_count": 1,
                "content_b64": "Y2FwdHVyZQ==",
                "redacted": False,
            }
        ],
    }
    if profile is not None:
        body["content_capture_profile"] = profile
    if include_capture_marker:
        body["capture_only"] = True
    return {
        "body": body,
        "kind": "call",
        "method": "observation_ingest",
        "protocol_version": "1.0",
        "rpc_id": _RPC_ID,
        "service_generation": "1",
        "service_instance_id": _INSTANCE_ID,
    }


@pytest.mark.parametrize(
    ("source", "profile", "mapping"),
    (
        ("claude_hook", "claude-code-ordinary-observation-v1", "claude-code-hooks-ordinary-v2"),
        ("cursor_hook", "cursor-ordinary-observation-v1", "cursor-hooks-ordinary-v1"),
        ("codex_hook", None, "codex-obs-hook/1.0.0"),
    ),
)
def test_v25_accepts_matching_native_capture_arms_and_keeps_outer_protocol_1_0(
    source: str, profile: str | None, mapping: str
) -> None:
    frame = _native_frame(source=source, profile=profile, mapping=mapping)

    validate_schema_instance("control-request", "2.5.0", cast(JsonValue, frame))
    assert frame["protocol_version"] == "1.0"
    decoded = decode_control_frame(encode_control_frame(cast(JsonValue, frame)))
    assert canonical_encode(decoded) == canonical_encode(cast(JsonValue, frame))


def test_v25_rejects_a_profile_on_the_profileless_codex_arm() -> None:
    frame = _native_frame(source="codex_hook", profile=None, mapping="codex-obs-hook/1.0.0")
    cast(dict[str, Any], frame["body"])["content_capture_profile"] = (
        "claude-code-ordinary-observation-v1"
    )
    with pytest.raises(ProtocolValueError):
        validate_schema_instance("control-request", "2.5.0", cast(JsonValue, frame))


def test_v24_rejects_native_capture_while_ordinary_body_remains_compatible() -> None:
    capture = _native_frame()
    with pytest.raises(ProtocolValueError):
        validate_schema_instance("control-request", "2.4.0", cast(JsonValue, capture))

    ordinary = _native_frame(include_capture_marker=False)
    validate_schema_instance("control-request", "2.4.0", cast(JsonValue, ordinary))
    validate_schema_instance("control-request", "2.5.0", cast(JsonValue, ordinary))


@pytest.mark.parametrize(
    "mutation",
    (
        "false-marker",
        "string-marker",
        "wrong-profile",
        "wrong-source",
        "empty-chunks",
        "chunks-not-array",
        "missing-profile",
        "missing-chunks",
        "unknown-body-field",
        "unknown-envelope-field",
        "wrong-method",
    ),
)
def test_v25_rejects_invalid_capture_arms_and_non_ingest_wrapper(mutation: str) -> None:
    frame = deepcopy(_native_frame())
    body = cast(dict[str, Any], frame["body"])
    envelope = cast(dict[str, Any], body["envelope"])
    if mutation == "false-marker":
        body["capture_only"] = False
    elif mutation == "string-marker":
        body["capture_only"] = "true"
    elif mutation == "wrong-profile":
        body["content_capture_profile"] = "cursor-ordinary-observation-v1"
    elif mutation == "wrong-source":
        envelope["source"] = "cursor_hook"
    elif mutation == "empty-chunks":
        body["content_chunks"] = []
    elif mutation == "chunks-not-array":
        body["content_chunks"] = "capture"
    elif mutation == "missing-profile":
        body.pop("content_capture_profile")
    elif mutation == "missing-chunks":
        body.pop("content_chunks")
    elif mutation == "unknown-body-field":
        body["unknown_capture_field"] = True
    elif mutation == "unknown-envelope-field":
        envelope["unknown_capture_field"] = True
    elif mutation == "wrong-method":
        frame["method"] = "service_status"
    else:
        raise AssertionError(mutation)

    with pytest.raises(ProtocolValueError):
        validate_schema_instance("control-request", "2.5.0", cast(JsonValue, frame))
