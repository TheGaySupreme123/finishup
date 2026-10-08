"""Frozen local-service control schema matrix and trust-boundary checks."""

from __future__ import annotations

import json
from collections.abc import Iterator
from copy import deepcopy
from importlib import resources
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

import pytest

from yoetz.domain.observation import _STRUCTURAL_KEYS  # pyright: ignore[reportPrivateUsage]
from yoetz.domain.values import JsonObject
from yoetz.ports.control import ControlCallRequest
from yoetz.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from yoetz.protocol.errors import ProtocolValueError
from yoetz.protocol.schemas import load_schema_catalog, validate_schema_instance
from yoetz.service.control_protocol import (
    decode_control_frame,
    encode_control_frame,
    parse_control_request,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]
_ROOT = _REPO_ROOT / "schemas" / "service"
_PACKAGE_ROOT = resources.files("yoetz").joinpath("resources", "schemas", "service")
_VERSION = "1.0.0"
_INSTANCE_ID = "svc_00000000-0000-4000-8000-000000000001"
_RPC_ID = "rpc_00000000-0000-4000-8000-000000000002"
_REQUEST_ID = "req_00000000-0000-4000-8000-000000000003"
_DIGEST = "sha256:" + "0" * 64
# Routine-read summaries use a separate observation envelope. These structural keys are therefore
# intentionally absent from the ordinary native capture control envelope, even though the domain
# observation validator admits them for that summary lane.
_ROUTINE_SUMMARY_STRUCTURAL_KEYS = frozenset(
    {
        "summary_count",
        "input_count",
        "member_digest",
        "fence",
        "provenance",
        "summary_schema",
        "selection_policy_version",
        "content_scope",
        "coverage_gaps",
        "subject_state_digest",
        "members",
        "selection_task_id",
        "selection_session_id",
        "selection_writer_id",
        "selection_authority_generation",
        "protection_reference",
    }
)
_WORKFLOW_METHODS = (
    "check",
    "publish_work",
    "receipt",
    "respond",
    "start",
    "status",
)
_SUPPORT_METHODS = (
    "backup_execute",
    "backup_preview",
    "import_codex_jsonl",
    "integration_execute",
    "integration_preview",
    "migrate_execute",
    "migrate_preview",
    "observation_ingest",
    "observation_pause",
    "observation_resume",
    "observation_revoke",
    "observation_status",
    "privacy_get_effective",
    "privacy_get_setup",
    "privacy_pending_list",
    "privacy_propose_policy",
    "privacy_receipts_get",
    "privacy_receipts_list",
    "privacy_tighten_policy",
    "restore_execute",
    "restore_preview",
    "review",
    "service_lock",
    "service_status",
    "service_stop",
)
_ALL_METHODS = tuple(sorted((*_WORKFLOW_METHODS, *_SUPPORT_METHODS)))
_CONTROL_ERROR_CODES = (
    "protocol_mismatch",
    "frame_invalid",
    "frame_too_large",
    "request_cancelled",
    "request_timeout",
    "vault_locked",
    "service_draining",
    "method_forbidden",
    "service_generation_changed",
    "internal_error",
)


def _schema(name: str) -> dict[str, Any]:
    return cast(
        dict[str, Any], strict_json_parse((_ROOT / f"{name}-{_VERSION}.schema.json").read_bytes())
    )


def _valid_status(*, ready: bool = False) -> dict[str, JsonValue]:
    if ready:
        return {
            "protocol_version": "1.0",
            "service_version": "0.1.0",
            "service_instance_id": _INSTANCE_ID,
            "service_generation": "1",
            "state": "ready",
            "state_reason": "human_authority_unavailable",
            "vault_mode": "os_keyring",
            "capabilities": [
                "confidential_ingress",
                "import_review",
                "maintenance",
                "session_event_monitor",
                "workflow",
            ],
            "session_monitor": "active",
            "idle_relock_seconds": 60,
        }
    return {
        "protocol_version": "1.0",
        "service_version": "0.1.0",
        "service_instance_id": _INSTANCE_ID,
        "service_generation": "1",
        "state": "locked",
        "state_reason": "human_authority_unavailable",
        "vault_mode": "uninitialized",
        "capabilities": [],
        "session_monitor": "unavailable",
    }


def _assert_invalid(name: str, value: JsonValue) -> None:
    with pytest.raises(ProtocolValueError) as caught:
        validate_schema_instance(name, _VERSION, value)
    assert caught.value.reason_code == "schema_instance_invalid"


def _walk(node: object) -> Iterator[tuple[str, object]]:
    if isinstance(node, dict):
        for key, value in cast(dict[str, object], node).items():
            yield key, value
            yield from _walk(value)
    elif isinstance(node, list):
        for value in cast(list[object], node):
            yield from _walk(value)


def test_five_service_schemas_are_root_package_identical_and_offline() -> None:
    names = (
        "control-hello",
        "control-hello-result",
        "control-request",
        "control-result",
        "service-status",
    )
    known_ids = set(load_schema_catalog().by_id)
    for name in names:
        filename = f"{name}-{_VERSION}.schema.json"
        root_bytes = (_ROOT / filename).read_bytes()
        assert root_bytes == _PACKAGE_ROOT.joinpath(filename).read_bytes()
        document = _schema(name)
        for key, value in _walk(document):
            if key != "$ref":
                continue
            ref = cast(str, value)
            parsed = urlparse(ref)
            if not parsed.scheme:
                assert ref.startswith("#/")
            else:
                assert parsed.scheme == "https"
                assert parsed.netloc == "schemas.yoetz.dev"
                assert ref.split("#", 1)[0] in known_ids


def test_hello_status_and_client_kind_authority_matrix() -> None:
    hello: dict[str, JsonValue] = {
        "protocol_version": "1.0",
        "client_kind": "mcp_bridge",
        "client_version": "0.1.0",
        "connection_nonce": "0" * 64,
        "schema_manifest_digest": _DIGEST,
    }
    validate_schema_instance("control-hello", _VERSION, hello)
    for invalid_nonce in ("0" * 63, "A" * 64, "g" * 64):
        candidate = dict(hello)
        candidate["connection_nonce"] = invalid_nonce
        _assert_invalid("control-hello", candidate)

    locked = _valid_status()
    ready_local = _valid_status(ready=True)
    validate_schema_instance("service-status", _VERSION, locked)
    validate_schema_instance("service-status", _VERSION, ready_local)
    assert "workflow" not in cast(list[str], locked["capabilities"])
    assert "external_provider" not in cast(list[str], locked["capabilities"])
    assert "external_provider" not in cast(list[str], ready_local["capabilities"])

    for allowed in (_WORKFLOW_METHODS, _ALL_METHODS):
        result: dict[str, JsonValue] = {
            "protocol_version": "1.0",
            "service_version": "0.1.0",
            "service_instance_id": _INSTANCE_ID,
            "service_generation": "1",
            "status": locked,
            "allowed_methods": list(allowed),
            "schema_manifest_digest": _DIGEST,
        }
        validate_schema_instance("control-hello-result", _VERSION, result)

    widened: dict[str, JsonValue] = {
        "protocol_version": "1.0",
        "service_version": "0.1.0",
        "service_instance_id": _INSTANCE_ID,
        "service_generation": "1",
        "status": locked,
        "allowed_methods": cast(list[JsonValue], [*_WORKFLOW_METHODS, "import_codex_jsonl"]),
        "schema_manifest_digest": _DIGEST,
    }
    _assert_invalid("control-hello-result", widened)


def test_v2_hello_adds_only_an_optional_ephemeral_workspace_locator() -> None:
    hello: dict[str, JsonValue] = {
        "protocol_version": "1.0",
        "client_kind": "cli",
        "client_version": "0.1.0",
        "connection_nonce": "0" * 64,
        "schema_manifest_digest": _DIGEST,
        "workspace_locator": {"schema_version": "1.0.0", "path": "/tmp/repository"},
    }
    validate_schema_instance("control-hello", "2.0.0", hello)
    with pytest.raises(ProtocolValueError):
        validate_schema_instance("control-hello", "1.0.0", hello)
    for invalid_locator in (
        {"schema_version": "1.0.0", "path": "relative"},
        {"schema_version": "1.0.0", "path": "/tmp/repository", "extra": True},
        {"schema_version": "2.0.0", "path": "/tmp/repository"},
    ):
        candidate = deepcopy(hello)
        candidate["workspace_locator"] = cast(JsonValue, invalid_locator)
        with pytest.raises(ProtocolValueError):
            validate_schema_instance("control-hello", "2.0.0", candidate)


def test_v2_repository_privacy_bodies_are_closed_and_v1_is_retained() -> None:
    request_schema = cast(
        dict[str, Any],
        strict_json_parse((_ROOT / "control-request-2.0.0.schema.json").read_bytes()),
    )
    result_schema = cast(
        dict[str, Any],
        strict_json_parse((_ROOT / "control-result-2.0.0.schema.json").read_bytes()),
    )
    request_defs = cast(dict[str, dict[str, Any]], request_schema["$defs"])
    setup_request_union = request_defs["privacy_get_setup_body"]
    assert len(setup_request_union["oneOf"]) == 2
    setup_request = setup_request_union["oneOf"][1]
    assert setup_request["additionalProperties"] is False
    assert setup_request["required"] == ["schema_version"]
    assert setup_request["properties"] == {"schema_version": {"const": "2.0.0"}}
    proposal_request_union = request_defs["privacy_propose_policy_body"]
    assert len(proposal_request_union["oneOf"]) == 2
    proposal_request = proposal_request_union["oneOf"][1]
    assert proposal_request["additionalProperties"] is False
    assert set(proposal_request["required"]) == {
        "schema_version",
        "authority_digest",
        "candidate_policy",
    }
    assert "expected_policy_digest" not in proposal_request["properties"]

    result_defs = cast(dict[str, dict[str, Any]], result_schema["$defs"])
    setup_result_union = result_defs["privacy_get_setup_body"]
    assert len(setup_result_union["oneOf"]) == 2
    setup_result = setup_result_union["oneOf"][1]
    assert setup_result["additionalProperties"] is False
    assert set(setup_result["required"]) == {
        "schema_version",
        "composed_policy",
        "bound_scope",
        "authority_digest",
        "grant_state",
        "migration_state",
        "channel_choices",
        "allowed_blocked_examples",
        "recipes",
        "never_send_editable",
        "privacy_projection",
    }
    assert setup_result["properties"]["never_send_editable"] == {"const": False}
    assert len(result_defs["privacy_propose_policy_body"]["oneOf"]) == 4
    v1_defs = cast(dict[str, dict[str, Any]], _schema("control-request")["$defs"])
    assert "expected_policy_digest" in v1_defs["privacy_propose_policy_body"]["properties"]


def test_v21_appends_cursor_observation_wire_without_rewriting_v2() -> None:
    request_v2 = cast(
        dict[str, Any],
        strict_json_parse((_ROOT / "control-request-2.0.0.schema.json").read_bytes()),
    )
    request_v21 = cast(
        dict[str, Any],
        strict_json_parse((_ROOT / "control-request-2.1.0.schema.json").read_bytes()),
    )
    result_v2 = cast(
        dict[str, Any],
        strict_json_parse((_ROOT / "control-result-2.0.0.schema.json").read_bytes()),
    )
    result_v21 = cast(
        dict[str, Any],
        strict_json_parse((_ROOT / "control-result-2.1.0.schema.json").read_bytes()),
    )

    request_v2_defs = cast(dict[str, dict[str, Any]], request_v2["$defs"])
    request_v21_defs = cast(dict[str, dict[str, Any]], request_v21["$defs"])
    source_v2 = request_v2_defs["observation_envelope"]["properties"]["source"]
    source_v21 = request_v21_defs["observation_envelope"]["properties"]["source"]
    assert source_v2["enum"] == ["codex_hook", "codex_session_stream"]
    assert source_v21["enum"] == ["codex_hook", "codex_session_stream", "cursor_hook"]

    changed_v2 = request_v2_defs["observation_envelope"]["properties"]["structural_payload"][
        "properties"
    ]["changed_paths_digest"]
    changed_v21 = request_v21_defs["observation_envelope"]["properties"]["structural_payload"][
        "properties"
    ]["changed_paths_digest"]
    assert changed_v2["pattern"] == "^sha256:[0-9a-f]{64}$"
    assert [branch["pattern"] for branch in changed_v21["oneOf"]] == [
        "^sha256:[0-9a-f]{64}$",
        "^hmac-sha256:[0-9a-f]{64}$",
    ]

    result_v2_defs = cast(dict[str, dict[str, Any]], result_v2["$defs"])
    result_v21_defs = cast(dict[str, dict[str, Any]], result_v21["$defs"])
    coverage_v2 = result_v2_defs["observation_status"]["properties"]["source_coverage"]
    coverage_v21 = result_v21_defs["observation_status"]["properties"]["source_coverage"]
    assert set(coverage_v2["properties"]) == {"codex_hook", "codex_session_stream"}
    assert set(coverage_v21["properties"]) == {
        "codex_hook",
        "codex_session_stream",
        "cursor_hook",
    }

    for filename in ("control-request-2.1.0.schema.json", "control-result-2.1.0.schema.json"):
        assert (_ROOT / filename).read_bytes() == _PACKAGE_ROOT.joinpath(filename).read_bytes()


def _cursor_ingest_frame(structural: dict[str, Any]) -> dict[str, Any]:
    return {
        "body": {
            "codex_session_id": "cursor:session-1",
            "envelope": {
                "content_object_refs": [],
                "cursor": {
                    "byte_position": 0,
                    "event_position": 1,
                    "last_source_commitment": "hmac-sha256:" + "0" * 64,
                    "mapping_version": "cursor-local-3.17",
                    "source_generation": 1,
                },
                "event_kind": "session_start",
                "gap_codes": [],
                "receipt_time": "2026-08-24T00:00:00.000Z",
                "session_commitment": "hmac-sha256:" + "1" * 64,
                "source": "cursor_hook",
                "source_identity": "hook:cursor",
                "structural_payload": structural,
            },
        },
        "kind": "call",
        "method": "observation_ingest",
        "protocol_version": "1.0",
        "rpc_id": _RPC_ID,
        "service_generation": "1",
        "service_instance_id": _INSTANCE_ID,
    }


def _current_cli_observation_frame(
    *, source: str, codex_session_id: str, structural: dict[str, Any]
) -> dict[str, Any]:
    """Build the control frame emitted after native Claude/Cursor hook sanitization."""

    return {
        "body": {
            "codex_session_id": codex_session_id,
            "envelope": {
                "content_object_refs": [],
                "cursor": {
                    "byte_position": 0,
                    "event_position": 1,
                    "last_source_commitment": "hmac-sha256:" + "0" * 64,
                    "mapping_version": "native-hook-test-1",
                    "source_generation": 1,
                },
                "event_kind": "PostToolUse",
                "gap_codes": [],
                "receipt_time": "2026-08-24T00:00:00.000Z",
                "session_commitment": "hmac-sha256:" + "1" * 64,
                "source": source,
                "source_identity": "hook:native",
                "structural_payload": structural,
            },
        },
        "kind": "call",
        "method": "observation_ingest",
        "protocol_version": "1.0",
        "rpc_id": _RPC_ID,
        "service_generation": "1",
        "service_instance_id": _INSTANCE_ID,
    }


def test_v21_wire_admits_the_exact_cursor_structural_tokens_hook_ingress_sends() -> None:
    """The 2.1.0 request wire must carry every structural key Cursor ingress can emit.

    ``structural_payload`` is ``additionalProperties: false``, so an omitted key here is not a
    lenient default: it makes the observation undeliverable at the boundary.
    """

    frame = _cursor_ingest_frame(
        {
            "capability_profile_id": "cursor-local-3.17",
            "cursor_version": "3.17.8",
            "hook_name": "sessionStart",
            "model_effort": "medium",
            "model_id": "claude-4.5-sonnet",
        }
    )

    validate_schema_instance("control-request", "2.1.0", cast(JsonValue, frame))

    # The domain admits ``:`` in these three structural tokens, so the wire must too or the same
    # class of undeliverable observation returns for a namespaced model identity.
    colon_bearing = _cursor_ingest_frame(
        {"model_id": "anthropic:claude-4.5-sonnet", "model_effort": "high"}
    )
    validate_schema_instance("control-request", "2.1.0", cast(JsonValue, colon_bearing))

    unknown = _cursor_ingest_frame({"cursor_version": "3.17.8", "cursor_workspace_path": "/tmp"})
    with pytest.raises(ProtocolValueError):
        validate_schema_instance("control-request", "2.1.0", cast(JsonValue, unknown))


def test_v22_adds_only_the_claude_hook_source_and_coverage_cell() -> None:
    request_v21 = cast(
        dict[str, Any],
        strict_json_parse((_ROOT / "control-request-2.1.0.schema.json").read_bytes()),
    )
    request_v22 = cast(
        dict[str, Any],
        strict_json_parse((_ROOT / "control-request-2.2.0.schema.json").read_bytes()),
    )
    result_v21 = cast(
        dict[str, Any],
        strict_json_parse((_ROOT / "control-result-2.1.0.schema.json").read_bytes()),
    )
    result_v22 = cast(
        dict[str, Any],
        strict_json_parse((_ROOT / "control-result-2.2.0.schema.json").read_bytes()),
    )
    source_v21 = request_v21["$defs"]["observation_envelope"]["properties"]["source"]
    source_v22 = request_v22["$defs"]["observation_envelope"]["properties"]["source"]
    assert source_v21["enum"] == ["codex_hook", "codex_session_stream", "cursor_hook"]
    assert source_v22["enum"] == [
        "codex_hook",
        "codex_session_stream",
        "cursor_hook",
        "claude_hook",
    ]
    coverage_v21 = result_v21["$defs"]["observation_status"]["properties"]["source_coverage"]
    coverage_v22 = result_v22["$defs"]["observation_status"]["properties"]["source_coverage"]
    assert set(coverage_v21["properties"]) == {
        "codex_hook",
        "codex_session_stream",
        "cursor_hook",
    }
    assert set(coverage_v22["properties"]) == {
        "claude_hook",
        "codex_hook",
        "codex_session_stream",
        "cursor_hook",
    }
    for filename in ("control-request-2.2.0.schema.json", "control-result-2.2.0.schema.json"):
        assert (_ROOT / filename).read_bytes() == _PACKAGE_ROOT.joinpath(filename).read_bytes()


def test_v23_updates_only_the_status_operation_schema_refs() -> None:
    request_v22 = cast(
        dict[str, Any],
        strict_json_parse((_ROOT / "control-request-2.2.0.schema.json").read_bytes()),
    )
    request_v23 = cast(
        dict[str, Any],
        strict_json_parse((_ROOT / "control-request-2.3.0.schema.json").read_bytes()),
    )
    result_v22 = cast(
        dict[str, Any],
        strict_json_parse((_ROOT / "control-result-2.2.0.schema.json").read_bytes()),
    )
    result_v23 = cast(
        dict[str, Any],
        strict_json_parse((_ROOT / "control-result-2.3.0.schema.json").read_bytes()),
    )

    old_request_id = request_v22.pop("$id")
    new_request_id = request_v23.pop("$id")
    old_result_id = result_v22.pop("$id")
    new_result_id = result_v23.pop("$id")
    request_v22_text = str(request_v22)
    result_v22_text = str(result_v22)
    assert "status-request-1.0.0.schema.json" in request_v22_text
    assert "status-result-1.0.0.schema.json" in result_v22_text

    def replace_status_version(value: object) -> None:
        if isinstance(value, dict):
            mapping = cast(dict[str, object], value)
            for key, member in mapping.items():
                if key == "$ref" and isinstance(member, str):
                    replaced = member.replace("status-request-1.1.0", "status-request-1.0.0")
                    mapping[key] = replaced.replace("status-result-1.1.0", "status-result-1.0.0")
                else:
                    replace_status_version(member)
        elif isinstance(value, list):
            for member in cast(list[object], value):
                replace_status_version(member)

    replace_status_version(request_v23)
    replace_status_version(result_v23)
    assert request_v23 == request_v22
    assert result_v23 == result_v22
    assert old_request_id.endswith("control-request-2.2.0.schema.json")
    assert new_request_id.endswith("control-request-2.3.0.schema.json")
    assert old_result_id.endswith("control-result-2.2.0.schema.json")
    assert new_result_id.endswith("control-result-2.3.0.schema.json")
    for filename in ("control-request-2.3.0.schema.json", "control-result-2.3.0.schema.json"):
        assert (_ROOT / filename).read_bytes() == _PACKAGE_ROOT.joinpath(filename).read_bytes()


def test_v24_updates_publish_provenance_privacy_and_ordinary_content_contracts() -> None:
    request_v23 = cast(
        dict[str, Any],
        strict_json_parse((_ROOT / "control-request-2.3.0.schema.json").read_bytes()),
    )
    request_v24 = cast(
        dict[str, Any],
        strict_json_parse((_ROOT / "control-request-2.4.0.schema.json").read_bytes()),
    )
    result_v23 = cast(
        dict[str, Any],
        strict_json_parse((_ROOT / "control-result-2.3.0.schema.json").read_bytes()),
    )
    result_v24 = cast(
        dict[str, Any],
        strict_json_parse((_ROOT / "control-result-2.4.0.schema.json").read_bytes()),
    )

    old_request_id = request_v23.pop("$id")
    new_request_id = request_v24.pop("$id")
    old_result_id = result_v23.pop("$id")
    new_result_id = result_v24.pop("$id")
    assert "publish-work-request-1.0.0.schema.json" in str(request_v23)
    assert "publish-work-request-1.1.0.schema.json" in str(request_v24)

    structural_v23 = request_v23["$defs"]["observation_envelope"]["properties"][
        "structural_payload"
    ]["properties"]
    structural_v24 = request_v24["$defs"]["observation_envelope"]["properties"][
        "structural_payload"
    ]["properties"]
    pairing_fields = ("pairing_mode", "correlation_kind", "generation_id")
    assert all(name not in structural_v23 for name in pairing_fields)
    assert structural_v24["pairing_mode"] == {
        "enum": ["paired", "post_only"],
        "type": "string",
    }
    assert structural_v24["correlation_kind"] == {
        "enum": ["tool_call_id", "generation_id", "none"],
        "type": "string",
    }
    assert structural_v24["generation_id"]["pattern"] == ("^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$")
    check_v24 = next(
        branch
        for branch in request_v24["oneOf"]
        if branch.get("properties", {}).get("method", {}).get("const") == "check"
    )
    assert check_v24["properties"]["host_profile"] == {
        "enum": ["generic", "codex", "claude", "cursor"],
        "type": "string",
    }

    # Strip the current-schema additions before comparing the historical
    # contract below. This keeps the existing byte-preservation assertion
    # precise while making the v2.4-only expansion explicit above.
    for name in pairing_fields:
        del structural_v24[name]
    del check_v24["properties"]["host_profile"]
    request_v24_defs = cast(dict[str, dict[str, Any]], request_v24["$defs"])
    request_v24_ingest = request_v24_defs["observation_ingest_body"]
    content_profile = cast(
        dict[str, Any],
        cast(dict[str, Any], request_v24_ingest["properties"])["content_capture_profile"],
    )
    assert content_profile == {
        "enum": [
            "claude-code-ordinary-observation-v1",
            "cursor-ordinary-observation-v1",
        ],
        "type": "string",
    }
    # This selector is the only ordinary-observation wire addition in 2.4;
    # remove it before comparing the inherited 2.3 contract below.
    del cast(dict[str, Any], request_v24_ingest["properties"])["content_capture_profile"]

    policy_ref = "https://schemas.yoetz.dev/0.1/privacy/privacy-policy-1.0.0.schema.json"
    policy_union = [
        {"$ref": policy_ref},
        {"$ref": policy_ref.replace("1.0.0", "1.1.0")},
    ]
    assert str(request_v24).count("privacy-policy-1.1.0.schema.json") == 3

    def restore_refs(value: object, replacements: tuple[tuple[str, str], ...]) -> None:
        if isinstance(value, dict):
            mapping = cast(dict[str, object], value)
            if mapping == {"anyOf": policy_union}:
                mapping.clear()
                mapping["$ref"] = policy_ref
                return
            for key, member in mapping.items():
                if key == "$ref" and isinstance(member, str):
                    for new_ref, old_ref in replacements:
                        member = member.replace(new_ref, old_ref)
                    mapping[key] = member
                else:
                    restore_refs(member, replacements)
        elif isinstance(value, list):
            for member in cast(list[object], value):
                restore_refs(member, replacements)

    restore_refs(
        request_v24,
        (("publish-work-request-1.1.0", "publish-work-request-1.0.0"),),
    )
    assert request_v24 == request_v23
    restore_refs(
        result_v24,
        (
            ("check-result-1.1.0", "check-result-1.0.0"),
            ("receipt-result-1.1.0", "receipt-result-1.0.0"),
            ("status-result-1.2.0", "status-result-1.1.0"),
            ("privacy-policy-1.1.0", "privacy-policy-1.0.0"),
        ),
    )
    assert result_v24 == result_v23
    assert old_request_id.endswith("control-request-2.3.0.schema.json")
    assert new_request_id.endswith("control-request-2.4.0.schema.json")
    assert old_result_id.endswith("control-result-2.3.0.schema.json")
    assert new_result_id.endswith("control-result-2.4.0.schema.json")
    for stem in ("control-hello", "control-hello-result", "control-request", "control-result"):
        filename = f"{stem}-2.4.0.schema.json"
        assert (_ROOT / filename).read_bytes() == _PACKAGE_ROOT.joinpath(filename).read_bytes()


def test_v25_observation_wire_tracks_domain_structural_keys_without_rewriting_v24() -> None:
    request_v24 = cast(
        dict[str, Any],
        strict_json_parse((_ROOT / "control-request-2.4.0.schema.json").read_bytes()),
    )
    request_v25 = cast(
        dict[str, Any],
        strict_json_parse((_ROOT / "control-request-2.5.0.schema.json").read_bytes()),
    )
    v24_properties = request_v24["$defs"]["observation_envelope"]["properties"][
        "structural_payload"
    ]["properties"]
    v25_properties = request_v25["$defs"]["observation_envelope"]["properties"][
        "structural_payload"
    ]["properties"]
    expected_observation_keys = (
        set(_STRUCTURAL_KEYS)
        - _ROUTINE_SUMMARY_STRUCTURAL_KEYS
        - {
            "lineage_child_task_id",
            "lineage_child_session_id",
            "lineage_child_writer_id",
            "lineage_parent_task_id",
            # The keyed command identity is additive on the unreleased 2.9 request wire (#909).
            "command_commitment",
            # So is the command runner class every tool observation carries.
            "runner_class",
            # And the closed runtime facts a hook classifies (#977).
            "install_target",
            "write_scope",
            "effective_user",
            # And the digest-only image facts (P3-2, issue #1013).
            "observed_images",
        }
    )
    assert set(v25_properties) == expected_observation_keys
    assert set(v24_properties) == expected_observation_keys
    assert v25_properties["pairing_mode"] == {
        "enum": ["paired", "post_only"],
        "type": "string",
    }
    assert v25_properties["correlation_kind"] == {
        "enum": ["tool_call_id", "generation_id", "none"],
        "type": "string",
    }
    assert v25_properties["generation_id"] == {
        "maxLength": 128,
        "minLength": 1,
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$",
        "type": "string",
    }


@pytest.mark.parametrize(
    ("source", "codex_session_id", "structural"),
    [
        (
            "claude_hook",
            "claude:session-1",
            {
                "action": "claude_mcp_success",
                "capability_profile_id": "claude-code-cli-local-project-2.1.241",
                "correlation_kind": "tool_call_id",
                "hook_name": "PostToolUse",
                "pairing_mode": "post_only",
                "tool_call_id": "tool-1",
            },
        ),
        (
            "cursor_hook",
            "cursor:session-1",
            {
                "action": "cursor_mcp",
                "capability_profile_id": "cursor-ide-3.17.8",
                "correlation_kind": "generation_id",
                "cursor_version": "3.17.8",
                "generation_id": "generation-1",
                "hook_name": "PostToolUse",
                "model_effort": "medium",
                "model_id": "claude-4.5-sonnet",
                "pairing_mode": "post_only",
                "tool_call_id": "tool-1",
            },
        ),
    ],
)
def test_v25_control_client_round_trips_cli_shaped_native_observation_frames(
    source: str, codex_session_id: str, structural: dict[str, Any]
) -> None:
    """The control admission preserves pairing metadata from the 2.4 wire onward."""

    frame = _current_cli_observation_frame(
        source=source,
        codex_session_id=codex_session_id,
        structural=structural,
    )
    validate_schema_instance("control-request", "2.5.0", cast(JsonValue, frame))

    parsed = parse_control_request(decode_control_frame(encode_control_frame(frame)))
    assert isinstance(parsed, ControlCallRequest)
    assert parsed.method.value == "observation_ingest"

    validate_schema_instance("control-request", "2.4.0", cast(JsonValue, frame))
    with pytest.raises(ProtocolValueError):
        validate_schema_instance("control-request", "2.3.0", cast(JsonValue, frame))


def test_v27_control_client_round_trips_selection_route_fields_without_rewriting_frozen_v26() -> (
    None
):
    """Current native hook envelopes carry the selection route on the active 2.7 wire only."""

    frame = _current_cli_observation_frame(
        source="claude_hook",
        codex_session_id="claude:session-1",
        structural={
            "action": "claude_mcp_success",
            "capability_profile_id": "claude-code-cli-local-project-2.1.241",
            "correlation_kind": "tool_call_id",
            "hook_name": "PostToolUse",
            "pairing_mode": "post_only",
            "selection_authority_generation": "sha256:" + "2" * 64,
            "selection_session_id": "ses_00000000-0000-4000-8000-000000000004",
            "selection_task_id": "tsk_00000000-0000-4000-8000-000000000005",
            "selection_writer_id": "wri_00000000-0000-4000-8000-000000000006",
            "success": True,
            "tool_call_id": "tool-1",
        },
    )

    validate_schema_instance("control-request", "2.7.0", cast(JsonValue, frame))
    parsed = parse_control_request(decode_control_frame(encode_control_frame(frame)))
    assert isinstance(parsed, ControlCallRequest)
    assert isinstance(parsed.body, JsonObject)
    assert canonical_encode(parsed.body) == canonical_encode(frame["body"])

    # The released 2.6 document remains byte-frozen and must not silently gain the
    # current selection routing extension.
    with pytest.raises(ProtocolValueError):
        validate_schema_instance("control-request", "2.6.0", cast(JsonValue, frame))


def test_v27_control_check_uses_current_request_wire_and_coordination_pack() -> None:
    """The active control envelope carries the project-aware check operation schema."""

    def operation_refs(filename: str) -> set[str]:
        document = cast(dict[str, Any], strict_json_parse((_ROOT / filename).read_bytes()))
        references: set[str] = set()

        def collect_refs(value: object) -> None:
            if isinstance(value, dict):
                mapping = cast(dict[str, object], value)
                reference = mapping.get("$ref")
                if isinstance(reference, str) and "/operations/" in reference:
                    references.add(reference.rsplit("/", 1)[-1])
                for member in mapping.values():
                    collect_refs(member)
            elif isinstance(value, list):
                for member in cast(list[object], value):
                    collect_refs(member)

        collect_refs(document)
        return references

    assert operation_refs("control-request-2.7.0.schema.json") == {
        "check-request-1.1.0.schema.json",
        "publish-work-request-1.2.0.schema.json",
        "receipt-request-1.0.0.schema.json",
        "respond-request-1.0.0.schema.json",
        "start-request-1.1.0.schema.json",
        "status-request-1.2.0.schema.json",
    }
    assert operation_refs("control-result-2.7.0.schema.json") == {
        "check-result-1.3.0.schema.json",
        "publish-work-result-1.0.0.schema.json",
        "receipt-result-1.3.0.schema.json",
        "respond-result-1.0.0.schema.json",
        "start-result-1.1.0.schema.json",
        "status-result-1.4.0.schema.json",
    }

    request: JsonValue = cast(
        JsonValue,
        {
            "kind": "call",
            "protocol_version": "1.0",
            "rpc_id": _RPC_ID,
            "service_instance_id": _INSTANCE_ID,
            "service_generation": "1",
            "method": "check",
            "body": {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": _REQUEST_ID,
                "session_id": "ses_00000000-0000-4000-8000-000000000004",
                "writer_id": "wri_00000000-0000-4000-8000-000000000005",
                "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
                "mode": "deterministic_only",
                "policy_packs": ["coordination/0.1.0"],
                "actor": {"actor_id": "harness:test", "actor_type": "harness"},
                "client": {
                    "kind": "test_client",
                    "version": "0.3.0",
                    "integration": "cooperative_mcp",
                },
            },
        },
    )
    validate_schema_instance("control-request", "2.7.0", request)
    with pytest.raises(ProtocolValueError):
        validate_schema_instance("control-request", "2.4.0", request)


def test_v24_pairing_structural_fields_round_trip_and_are_rejected_by_v23() -> None:
    """Pairing metadata is accepted on the active wire and closed in older versions."""

    frame = _cursor_ingest_frame(
        {
            "capability_profile_id": "cursor-ide-3.17.8",
            "correlation_kind": "generation_id",
            "generation_id": "turn-607",
            "pairing_mode": "post_only",
        }
    )
    validate_schema_instance("control-request", "2.4.0", cast(JsonValue, frame))
    with pytest.raises(ProtocolValueError):
        validate_schema_instance("control-request", "2.3.0", cast(JsonValue, frame))

    from yoetz.service.control_protocol import decode_control_frame, encode_control_frame

    encoded = encode_control_frame(cast(JsonValue, frame))
    decoded = decode_control_frame(encoded)
    assert canonical_encode(decoded) == canonical_encode(frame)


def test_control_request_and_result_unions_are_exact_and_disjoint() -> None:
    request_schema = _schema("control-request")
    result_schema = _schema("control-result")
    requests = cast(list[dict[str, Any]], request_schema["oneOf"])
    results = cast(list[dict[str, Any]], result_schema["oneOf"])

    assert len(requests) == 32
    assert len(results) == 62
    call_methods: list[str] = []
    cancel_count = 0
    for branch in requests:
        properties = cast(dict[str, dict[str, Any]], branch["properties"])
        assert branch["additionalProperties"] is False
        assert properties["protocol_version"]["const"] == "1.0"
        if properties["kind"]["const"] == "cancel":
            cancel_count += 1
            assert "method" not in properties
            assert "body" not in properties
            assert "target_rpc_id" in properties
        else:
            call_methods.append(cast(str, properties["method"]["const"]))
            assert properties["kind"]["const"] == "call"
            assert "body" in properties
    assert cancel_count == 1
    assert tuple(sorted(call_methods)) == _ALL_METHODS

    result_pairs: list[tuple[str, str]] = []
    for branch in results:
        properties = cast(dict[str, dict[str, Any]], branch["properties"])
        assert branch["additionalProperties"] is False
        method = cast(str, properties["method"]["const"])
        outcome = cast(str, properties["outcome"]["const"])
        result_pairs.append((method, outcome))
        body_ref = cast(str, properties["body"]["$ref"])
        if outcome == "error":
            assert body_ref == "#/$defs/error_body"
    assert tuple(sorted(result_pairs)) == tuple(
        sorted((method, outcome) for method in _ALL_METHODS for outcome in ("error", "ok"))
    )


def test_integration_requests_require_explicit_codex_harness() -> None:
    definitions = cast(dict[str, dict[str, Any]], _schema("control-request")["$defs"])
    preview_branches = cast(list[dict[str, Any]], definitions["integration_preview_body"]["oneOf"])
    execute_body = definitions["integration_execute_body"]
    for body in (*preview_branches, execute_body):
        properties = cast(dict[str, dict[str, Any]], body["properties"])
        assert properties["harness"] == {"const": "codex"}
        assert "harness" in cast(list[str], body["required"])

    bodies: tuple[tuple[str, dict[str, JsonValue]], ...] = (
        (
            "integration_preview",
            {
                "schema_version": "1.0.0",
                "operation": "preview",
                "request_id": _REQUEST_ID,
                "harness": "codex",
                "project_root": "/tmp/project",
                "action": "install",
                "replace_modified": False,
            },
        ),
        (
            "integration_preview",
            {
                "schema_version": "1.0.0",
                "operation": "status",
                "harness": "codex",
                "project_root": "/tmp/project",
            },
        ),
        (
            "integration_execute",
            {
                "schema_version": "1.0.0",
                "request_id": _REQUEST_ID,
                "harness": "codex",
                "project_root": "/tmp/project",
                "action": "install",
                "preview_digest": _DIGEST,
                "explicitly_accepted": True,
                "replace_modified": False,
            },
        ),
    )
    for method, body in bodies:
        request: dict[str, JsonValue] = {
            "kind": "call",
            "protocol_version": "1.0",
            "rpc_id": _RPC_ID,
            "service_instance_id": _INSTANCE_ID,
            "service_generation": "1",
            "method": method,
            "body": body,
        }
        validate_schema_instance("control-request", _VERSION, request)
        for invalid_harness in (None, "claude"):
            invalid = deepcopy(request)
            invalid_body = cast(dict[str, JsonValue], invalid["body"])
            if invalid_harness is None:
                del invalid_body["harness"]
            else:
                invalid_body["harness"] = invalid_harness
            _assert_invalid("control-request", invalid)


def test_envelope_identity_and_error_bodies_fail_closed() -> None:
    request: dict[str, JsonValue] = {
        "kind": "call",
        "protocol_version": "1.0",
        "rpc_id": _RPC_ID,
        "service_instance_id": _INSTANCE_ID,
        "service_generation": "1",
        "method": "service_status",
        "body": {},
    }
    validate_schema_instance("control-request", _VERSION, request)
    for field, bad in (
        ("protocol_version", "0.1"),
        ("rpc_id", "rpc_bad"),
        ("service_instance_id", "svc_bad"),
        ("service_generation", "01"),
        ("method", "unknown"),
        ("body", {"unknown": True}),
    ):
        candidate = deepcopy(request)
        candidate[field] = cast(JsonValue, bad)
        _assert_invalid("control-request", candidate)

    for code in _CONTROL_ERROR_CODES:
        result: dict[str, JsonValue] = {
            "protocol_version": "1.0",
            "rpc_id": _RPC_ID,
            "service_instance_id": _INSTANCE_ID,
            "service_generation": "1",
            "method": "service_status",
            "outcome": "error",
            "body": {"code": code, "retryable": False},
        }
        validate_schema_instance("control-result", _VERSION, result)
        for extra in ("message", "path", "username"):
            widened = deepcopy(result)
            cast(dict[str, JsonValue], widened["body"])[extra] = "not public"
            _assert_invalid("control-result", widened)

    confused = {
        "protocol_version": "1.0",
        "rpc_id": _RPC_ID,
        "service_instance_id": _INSTANCE_ID,
        "service_generation": "1",
        "method": "service_status",
        "outcome": "ok",
        "body": {"code": "internal_error", "retryable": False},
    }
    _assert_invalid("control-result", confused)


def test_status_bounds_backup_privacy_audit_and_confidential_absence() -> None:
    for idle in (60, 86_400):
        status = _valid_status(ready=True)
        status["idle_relock_seconds"] = idle
        validate_schema_instance("service-status", _VERSION, status)
    for idle in (59, 86_401, True, "60", None):
        status = _valid_status(ready=True)
        status["idle_relock_seconds"] = cast(JsonValue, idle)
        _assert_invalid("service-status", status)
    for capabilities in (
        ["workflow", "maintenance"],
        ["workflow", "workflow"],
    ):
        status = _valid_status(ready=True)
        status["capabilities"] = cast(list[JsonValue], capabilities)
        _assert_invalid("service-status", status)

    result_schema = _schema("control-result")
    definitions = cast(dict[str, dict[str, Any]], result_schema["$defs"])
    for definition_name in ("backup_preview_body", "backup_execute_body"):
        definition = definitions[definition_name]
        required = set(cast(list[str], definition["required"]))
        properties = cast(dict[str, Any], definition["properties"])
        assert {"privacy_audit_object_count", "privacy_audit_snapshot_digest"} <= required
        assert properties["privacy_audit_object_count"]["type"] == "integer"
        assert properties["privacy_audit_snapshot_digest"]["pattern"] == "^sha256:[0-9a-f]{64}$"
        assert "privacy_audit_content" not in properties
        assert "privacy_audit_path" not in properties

    forbidden_property_names = {
        "passphrase",
        "secret",
        "unlock",
        "provider_credential",
        "key_locator",
        "pid",
        "username",
    }
    for name in (
        "control-hello",
        "control-hello-result",
        "control-request",
        "control-result",
        "service-status",
    ):
        property_names = {
            key
            for key, value in _walk(_schema(name))
            if key not in {"properties", "$defs"} and value is not None
        }
        assert forbidden_property_names.isdisjoint(property_names)

    # Cross-field lifecycle combinations are intentionally owned by Wave C's ServiceStatus model;
    # the frozen schema only proves bounded structural serialization.


def test_v28_native_child_start_bridge_round_trip_preserves_frozen_v27() -> None:
    """Native correlation candidates need the successor closed control contract."""

    frame = _current_cli_observation_frame(
        source="codex_hook",
        codex_session_id="native-child-lane",
        structural={
            "hook_name": "PostToolUse",
            "tool_name": "mcp__yoetz__start",
            "subagent_id": "native-worker",
            "parent_tool_call_id": "spawn-call",
            "lineage_child_task_id": "tsk_00000000-0000-4000-8000-000000000001",
            "lineage_child_session_id": "ses_00000000-0000-4000-8000-000000000002",
            "lineage_child_writer_id": "wri_00000000-0000-4000-8000-000000000003",
            "lineage_parent_task_id": "tsk_00000000-0000-4000-8000-000000000004",
        },
    )
    validate_schema_instance("control-request", "2.8.0", cast(JsonValue, frame))
    parsed = parse_control_request(decode_control_frame(encode_control_frame(frame)))
    assert isinstance(parsed, ControlCallRequest)
    assert isinstance(parsed.body, JsonObject)
    assert canonical_encode(parsed.body) == canonical_encode(frame["body"])
    with pytest.raises(ProtocolValueError):
        validate_schema_instance("control-request", "2.7.0", cast(JsonValue, frame))


def _v29_custom_capacity_status_frame() -> dict[str, Any]:
    """Return an observation-status result whose runtime reports a custom finite capacity."""

    limits: dict[str, Any] = {
        "queue_count": 1024,
        "queue_bytes": 1_048_576,
        "state_bytes": 2_097_152,
        "pending_attempts": 256,
        "capture_tickets": 512,
        "capture_bytes": 134_217_728,
        "protected_count": 256,
        "protected_bytes": 262_144,
        "session_fair_share": 256,
        "session_fair_share_bytes": 262_144,
        "max_pending_age_ms": 60_000,
        "state_document_ceiling_bytes": 16_777_216,
    }
    effective_budget: dict[str, Any] = {
        "schema": "yoetz.observation-effective-budget/1",
        "budget_policy_version": "observation-budget-v2-provisional",
        "validation_status": "not_validated",
        "scope": "session",
        "selected_queue_count": 1024,
        "selected_capacity_label": "custom",
        "effective_queue_count": 1024,
        "effective_capacity_label": "custom",
        "effective_reason": "selected",
        "limits": limits,
        "limiting_dimension": "count",
        "utilization_bps": 19,
        "no_cap": {
            "available": False,
            "dimension": "structural_queue",
            "reason": "state_document_ceiling",
            "state_document_ceiling_bytes": 16_777_216,
            "largest_supported_queue_count": 8192,
        },
    }
    selection_runtime: dict[str, Any] = {
        "accounting": {
            "accounting_scope": "locally_ingested_since_selection_upgrade",
            "admitted_input_count": 3,
            "buffered_input_count": 1,
            "buffered_successful_call_count": 1,
            "check_selection": "reported_by_each_check",
            "delivered_input_count": 2,
            "intentionally_omitted_input_count": 1,
            "loss_identity_commitment": None,
            "loss_identity_list_complete": False,
            "loss_ranges": [],
            "observed_count": 4,
            "pending_attempt_count": 1,
            "selection_epoch": 3,
            "summarized_input_count": 1,
            "summary_record_count": 1,
            "unrecoverable_input_count": 0,
        },
        "admission_allowed": True,
        "capture_backlog": {
            "byte_count": 0,
            "capture_backlog_scope": "partial",
            "count": 0,
            "observed_at": "2026-09-10T00:00:01.000Z",
            "oldest_receipt_time": None,
            "reservation_count": 0,
            "reservation_unknown": False,
            "reserved_byte_count": 0,
            "route_count": 0,
            "routes": {},
        },
        "content_allowed": True,
        "effective_budget": effective_budget,
        "effective_capacity": 1024,
        "effective_capacity_label": "custom",
        "effective_mode": "focused",
        "oldest_pending_age_ms": 250,
        "pending_attempts": 1,
        "pending_lifecycle_count": 0,
        "policy_version": "observation-budget-v2-provisional",
        "pressure_state": "healthy",
        "pressure_transition_identity": None,
        "protected_bytes_reserve": 262_144,
        "protected_count_reserve": 256,
        "queue_bytes": 2048,
        "queue_count": 2,
        "selected_capacity": 1024,
        "selected_capacity_label": "custom",
        "selected_mode": "focused",
        "selection_expires_at": "2026-09-10T01:00:00.000Z",
        "selection_origin": "session",
        "session_commitment": "hmac-sha256:" + "1" * 64,
        "session_fair_share": 256,
        "session_fair_share_bytes": 262_144,
        "state_bytes": 4096,
        "validation_status": "not_validated",
    }
    return {
        "body": {
            "request_id": _REQUEST_ID,
            "schema_version": "1.0.0",
            "status": {
                "advice_frontier": None,
                "gaps": [],
                "lag_events": 0,
                "last_observation_receipt_time": "2026-09-10T00:00:01.000Z",
                "lifecycle": "active",
                "selection_runtime": selection_runtime,
                "source_coverage": {
                    "claude_hook": True,
                    "codex_hook": True,
                    "codex_session_stream": False,
                    "cursor_hook": False,
                },
                "unsupported_events": [],
                "workspace_commitment": "hmac-sha256:" + "1" * 64,
            },
        },
        "method": "observation_status",
        "outcome": "ok",
        "protocol_version": "1.0",
        "rpc_id": _RPC_ID,
        "service_generation": "1",
        "service_instance_id": _INSTANCE_ID,
    }


def test_v29_custom_capacity_runtime_validates_only_on_29_wire() -> None:
    """A custom finite capacity and its effective budget need the 2.9 control-result wire."""

    frame = _v29_custom_capacity_status_frame()
    validate_schema_instance("control-result", "2.9.0", cast(JsonValue, frame))
    decoded = decode_control_frame(encode_control_frame(frame))
    assert canonical_encode(decoded) == canonical_encode(cast(JsonValue, frame))
    with pytest.raises(ProtocolValueError) as caught:
        validate_schema_instance("control-result", "2.8.0", cast(JsonValue, frame))
    assert caught.value.reason_code == "schema_instance_invalid"

    def runtime(candidate: dict[str, Any]) -> dict[str, Any]:
        return cast(dict[str, Any], candidate["body"]["status"]["selection_runtime"])

    # Every profile label and the closed record stay bounded on the successor wire.
    mutations: tuple[tuple[str, Any], ...] = (
        ("selected_capacity", 63),
        ("effective_capacity", 8193),
        ("selected_capacity_label", "unlimited"),
        ("effective_capacity_label", None),
    )
    for key, value in mutations:
        invalid = deepcopy(frame)
        runtime(invalid)[key] = value
        with pytest.raises(ProtocolValueError):
            validate_schema_instance("control-result", "2.9.0", cast(JsonValue, invalid))
    for key in ("selected_capacity_label", "effective_capacity_label", "effective_budget"):
        invalid = deepcopy(frame)
        del runtime(invalid)[key]
        with pytest.raises(ProtocolValueError):
            validate_schema_instance("control-result", "2.9.0", cast(JsonValue, invalid))
    budget_mutations: tuple[tuple[tuple[str, ...], Any], ...] = (
        (("schema",), "yoetz.observation-effective-budget/2"),
        (("scope",), "machine"),
        (("effective_reason",), "largest"),
        (("limiting_dimension",), "unbounded"),
        (("utilization_bps",), -1),
        (("selected_queue_count",), 0),
        (("no_cap", "available"), True),
        (("no_cap", "reason"), "unsupported"),
        (("limits", "queue_bytes"), -1),
        (("limits", "unbounded"), 1),
        (("extra",), 1),
    )
    for path, value in budget_mutations:
        invalid = deepcopy(frame)
        target = cast(dict[str, Any], runtime(invalid)["effective_budget"])
        for step in path[:-1]:
            target = cast(dict[str, Any], target[step])
        target[path[-1]] = value
        with pytest.raises(ProtocolValueError):
            validate_schema_instance("control-result", "2.9.0", cast(JsonValue, invalid))
    for path in (("limits", "state_document_ceiling_bytes"), ("no_cap", "dimension"), ("scope",)):
        invalid = deepcopy(frame)
        target = cast(dict[str, Any], runtime(invalid)["effective_budget"])
        for step in path[:-1]:
            target = cast(dict[str, Any], target[step])
        del target[path[-1]]
        with pytest.raises(ProtocolValueError):
            validate_schema_instance("control-result", "2.9.0", cast(JsonValue, invalid))

    # The three reviewed profiles remain valid with their names on 2.9.
    for count, label in ((512, "standard"), (2048, "larger"), (8192, "largest")):
        profile = deepcopy(frame)
        runtime(profile).update(
            {
                "selected_capacity": count,
                "effective_capacity": count,
                "selected_capacity_label": label,
                "effective_capacity_label": label,
            }
        )
        validate_schema_instance("control-result", "2.9.0", cast(JsonValue, profile))


def _structural_properties(document: dict[str, Any]) -> dict[str, Any]:
    envelope = document["$defs"]["observation_envelope"]["oneOf"][0]
    return cast(dict[str, Any], envelope["properties"]["structural_payload"]["properties"])


def _assert_v29_request_adds_only_command_commitment(
    v28: dict[str, Any], v29: dict[str, Any]
) -> None:
    """The 2.9 request adds the keyed command identity, the runner class and the closed runtime
    facts (#909, #977) and nothing else."""

    v28_fields = _structural_properties(v28)
    v29_fields = _structural_properties(v29)
    assert set(v29_fields) - set(v28_fields) == {
        "command_commitment",
        "runner_class",
        "install_target",
        "write_scope",
        "effective_user",
        "observed_images",
    }
    image = v29_fields["observed_images"]
    assert image["maxItems"] == 8
    assert image["items"]["additionalProperties"] is False
    assert image["items"]["required"] == ["byte_count", "content_digest", "media_type"]
    assert image["items"]["properties"]["media_type"]["enum"] == [
        "image/gif",
        "image/jpeg",
        "image/png",
        "image/unknown",
        "image/webp",
    ]
    assert v29_fields["install_target"] == {
        "enum": ["private_env", "system", "unresolved", "workspace_env", "yoetz_runtime"],
        "type": "string",
    }
    assert v29_fields["write_scope"] == {"enum": ["outside_workspace"], "type": "string"}
    assert v29_fields["effective_user"] == {"enum": ["non_root", "root"], "type": "string"}
    assert v29_fields["runner_class"] == {
        "enum": ["build", "compound", "exploration", "lint", "other", "test", "typecheck", "vcs"],
        "type": "string",
    }
    assert v29_fields["command_commitment"] == {
        "maxLength": 76,
        "minLength": 76,
        "pattern": "^hmac-sha256:[0-9a-f]{64}$",
        "type": "string",
    }
    stripped = json.loads(json.dumps(v29))
    for added in (
        "command_commitment",
        "runner_class",
        "install_target",
        "write_scope",
        "effective_user",
        "observed_images",
    ):
        del _structural_properties(stripped)[added]
    assert {k: v for k, v in v28.items() if k != "$id"} == {
        k: v for k, v in stripped.items() if k != "$id"
    }


def test_v29_request_carries_keyed_command_commitment_never_command_text() -> None:
    """The unreleased 2.9 request admits the hook's keyed command identity only (#909)."""

    structural = {
        "action": "claude_tool_failure",
        "capability_profile_id": "claude-code-ordinary-observation-v1",
        "command_commitment": "hmac-sha256:" + "a" * 64,
        "correlation_kind": "tool_call_id",
        "hook_name": "PostToolUse",
        "pairing_mode": "post_only",
        "success": False,
        "tool_call_id": "tool-1",
        "tool_name": "Bash",
    }
    frame = _current_cli_observation_frame(
        source="claude_hook", codex_session_id="claude:session-1", structural=structural
    )
    validate_schema_instance("control-request", "2.9.0", cast(JsonValue, frame))
    with pytest.raises(ProtocolValueError):
        validate_schema_instance("control-request", "2.8.0", cast(JsonValue, frame))
    for rejected in ("sha256:" + "a" * 64, "pytest -q tests/x.py"):
        invalid = json.loads(json.dumps(frame))
        invalid["body"]["envelope"]["structural_payload"]["command_commitment"] = rejected
        with pytest.raises(ProtocolValueError):
            validate_schema_instance("control-request", "2.9.0", cast(JsonValue, invalid))
    invalid = json.loads(json.dumps(frame))
    invalid["body"]["envelope"]["structural_payload"]["command"] = "pytest -q tests/x.py"
    with pytest.raises(ProtocolValueError):
        validate_schema_instance("control-request", "2.9.0", cast(JsonValue, invalid))


def test_v29_request_admits_digest_only_image_facts_and_nothing_more() -> None:
    """P3-2 (issue #1013): an image result crosses as its digest, size, type, and header size."""

    image = {
        "byte_count": 68,
        "content_digest": "sha256:" + "b" * 64,
        "height": 2,
        "media_type": "image/png",
        "width": 3,
    }
    structural = {
        "action": "claude_tool_success",
        "capability_profile_id": "claude-code-ordinary-observation-v1",
        "correlation_kind": "tool_call_id",
        "hook_name": "PostToolUse",
        "observed_images": [
            image,
            {k: image[k] for k in ("byte_count", "content_digest")}
            | {"media_type": "image/unknown"},
        ],
        "pairing_mode": "post_only",
        "success": True,
        "tool_call_id": "tool-1",
        "tool_name": "Read",
    }
    frame = _current_cli_observation_frame(
        source="claude_hook", codex_session_id="claude:session-1", structural=structural
    )
    validate_schema_instance("control-request", "2.9.0", cast(JsonValue, frame))
    for key, value in (
        ("pixels", "AAAA"),
        ("media_type", "image/svg+xml"),
        ("width", 0),
        ("content_digest", None),
    ):
        invalid = cast(dict[str, Any], json.loads(json.dumps(frame)))
        item = cast(dict[str, Any], invalid["body"]["envelope"]["structural_payload"])[
            "observed_images"
        ][0]
        if value is None:
            del item[key]
        else:
            item[key] = value
        with pytest.raises(ProtocolValueError):
            validate_schema_instance("control-request", "2.9.0", cast(JsonValue, invalid))
    too_many = cast(dict[str, Any], json.loads(json.dumps(frame)))
    too_many["body"]["envelope"]["structural_payload"]["observed_images"] = [image] * 9
    with pytest.raises(ProtocolValueError):
        validate_schema_instance("control-request", "2.9.0", cast(JsonValue, too_many))


_POLICY_V12 = "https://schemas.yoetz.dev/0.1/privacy/privacy-policy-1.2.0.schema.json"


def _without_policy_v12(value: Any) -> Any:
    """Undo the one other 2.9 change: admitting the privacy-policy 1.2.0 wire (issue #908)."""

    if isinstance(value, list):
        return [_without_policy_v12(item) for item in cast(list[Any], value)]
    if not isinstance(value, dict):
        return value
    source = cast(dict[str, Any], value)
    branches = source.get("anyOf")
    if isinstance(branches, list) and {"$ref": _POLICY_V12} in branches:
        kept = [branch for branch in cast(list[Any], branches) if branch != {"$ref": _POLICY_V12}]
        return kept[0] if len(kept) == 1 else {**source, "anyOf": kept}
    if source.get("$ref") == _POLICY_V12 + "#/$defs/review_selection_policy":
        return {
            **source,
            "$ref": _POLICY_V12.replace("1.2.0", "1.0.0") + "#/$defs/review_selection_policy",
        }
    return {key: _without_policy_v12(item) for key, item in source.items()}


def test_v29_changes_only_the_selection_runtime_and_keeps_frozen_v28() -> None:
    """2.9 derives from 2.8 by one runtime definition, the partial receipt page (#921) and the
    privacy-policy 1.2.0 admission (issue #908), and bounded fault-stage attribution (#954);
    the 2.8 documents are not rewritten."""

    for name in ("control-hello", "control-hello-result", "control-request", "control-result"):
        v28 = cast(
            dict[str, Any], strict_json_parse((_ROOT / f"{name}-2.8.0.schema.json").read_bytes())
        )
        v29 = cast(
            dict[str, Any],
            _without_policy_v12(
                strict_json_parse((_ROOT / f"{name}-2.9.0.schema.json").read_bytes())
            ),
        )
        assert v28["$id"] == f"https://schemas.yoetz.dev/0.1/service/{name}-2.8.0.schema.json"
        assert v29["$id"] == f"https://schemas.yoetz.dev/0.1/service/{name}-2.9.0.schema.json"
        assert (_ROOT / f"{name}-2.9.0.schema.json").read_bytes() == _PACKAGE_ROOT.joinpath(
            f"{name}-2.9.0.schema.json"
        ).read_bytes()
        # 2.9.0 (unreleased) also moves to the respond 1.1.0 pair (issue #905), to the
        # check-result 1.4.0 review output (issue #961) and to the publish-work 1.1.0 result
        # that names the current policy-pack versions; undo those retargets before comparing,
        # so every other byte must still match frozen 2.8.
        v29 = cast(
            dict[str, Any],
            _without_policy_v12(
                strict_json_parse(
                    (_ROOT / f"{name}-2.9.0.schema.json")
                    .read_bytes()
                    .replace(b"respond-request-1.1.0", b"respond-request-1.0.0")
                    .replace(b"respond-result-1.1.0", b"respond-result-1.0.0")
                    .replace(b"check-result-1.4.0", b"check-result-1.3.0")
                    .replace(b"publish-work-result-1.1.0", b"publish-work-result-1.0.0")
                )
            ),
        )
        if name == "control-request":
            _assert_v29_request_adds_only_command_commitment(v28, v29)
            continue
        if name != "control-result":
            assert {k: v for k, v in v28.items() if k != "$id"} == {
                k: v for k, v in v29.items() if k != "$id"
            }
            continue
        v28_defs = cast(dict[str, Any], v28["$defs"])
        v29_defs = cast(dict[str, Any], v29["$defs"])
        assert set(v29_defs) - set(v28_defs) == {"observation_effective_budget"}
        changed = {key for key in v28_defs if v28_defs[key] != v29_defs[key]}
        assert changed == {
            "local_disclosure_receipt",
            "observation_selection_runtime",
            "privacy_receipt_view",
            "privacy_receipts_list_body",
            "privacy_get_setup_body",
            "error_body",
        }
        # Issue #982: the repository setup read gains only the optional, derived
        # possible-credential filter pair; removing it recovers the frozen 2.8 body exactly.
        v29_setup = json.loads(json.dumps(v29_defs["privacy_get_setup_body"]))
        for branch in v29_setup["oneOf"]:
            pair = branch["properties"].pop("credential_heuristic", None)
            if pair is not None:
                assert pair["required"] == ["machine_default", "repository"]
                assert "credential_heuristic" not in branch.get("required", [])
        assert v29_setup == v28_defs["privacy_get_setup_body"]
        # Issue #921: the receipt page gains only optional, paired partial-listing fields, and the
        # error vocabulary gains only the closed, non-retryable store-side reason.
        v28_page = cast(dict[str, Any], v28_defs["privacy_receipts_list_body"])
        v29_page = cast(dict[str, Any], v29_defs["privacy_receipts_list_body"])
        assert v29_page["required"] == v28_page["required"]
        assert set(v29_page["properties"]) - set(v28_page["properties"]) == {
            "undecodable_count",
            "undecodable_receipt_ids",
        }
        assert v29_page["dependentRequired"] == {
            "undecodable_count": ["undecodable_receipt_ids"],
            "undecodable_receipt_ids": ["undecodable_count"],
        }
        v28_errors = cast(list[Any], v28_defs["error_body"]["oneOf"])
        v29_errors = cast(list[Any], v29_defs["error_body"]["oneOf"])
        # A read failure may identify its service-owned stage. The field stays optional, and
        # stripping that one additive member must recover each frozen error branch exactly.
        for branch in v29_errors:
            assert branch["properties"].pop("phase") == {
                "type": "string",
                "pattern": "^[a-z][a-z0-9_]{0,63}$",
                "maxLength": 64,
            }
            assert "phase" not in branch["required"]
        added = [branch for branch in v29_errors if branch not in v28_errors]
        assert [branch for branch in v29_errors if branch in v28_errors] == v28_errors
        assert [branch["properties"]["code"] for branch in added] == [
            {"const": "privacy_audit_unreadable"}
        ]
        assert added[0]["properties"]["retryable"] == {"const": False}
        assert {k: v for k, v in v28.items() if k not in {"$id", "$defs"}} == {
            k: v for k, v in v29.items() if k not in {"$id", "$defs"}
        }
        v28_runtime = cast(dict[str, Any], v28_defs["observation_selection_runtime"])
        v29_runtime = cast(dict[str, Any], v29_defs["observation_selection_runtime"])
        assert v28_runtime["properties"]["selected_capacity"] == {
            "enum": [512, 2048, 8192],
            "type": "integer",
        }
        assert "effective_budget" not in v28_runtime["properties"]
        assert v29_runtime["properties"]["selected_capacity"] == {
            "maximum": 8192,
            "minimum": 64,
            "type": "integer",
        }
        assert v29_runtime["required"] == [
            *v28_runtime["required"],
            "selected_capacity_label",
            "effective_capacity_label",
            "effective_budget",
        ]
        budget = cast(dict[str, Any], v29_defs["observation_effective_budget"])
        assert budget["additionalProperties"] is False
        assert set(budget["required"]) == set(budget["properties"])
        assert budget["properties"]["no_cap"]["properties"]["available"] == {"const": False}


def test_v29_admits_the_evidence_author_filter_in_place() -> None:
    """Unreleased 0.3 status request 1.2.0 carries ``filter.author=mine`` in place (#914)."""

    request = cast(
        JsonValue,
        {
            "kind": "call",
            "protocol_version": "1.0",
            "rpc_id": _RPC_ID,
            "service_instance_id": _INSTANCE_ID,
            "service_generation": "1",
            "method": "status",
            "body": {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": _REQUEST_ID,
                "session_id": "ses_00000000-0000-4000-8000-000000000004",
                "writer_id": "wri_00000000-0000-4000-8000-000000000005",
                "view": "evidence",
                "limit": "100",
                "filter": {"author": "mine", "strength": "content_digest"},
                "actor": {"actor_id": "harness:test", "actor_type": "harness"},
                "client": {
                    "kind": "test_client",
                    "version": "0.3.0",
                    "integration": "cooperative_mcp",
                },
            },
        },
    )
    validate_schema_instance("control-request", "2.9.0", request)
    body = cast(dict[str, Any], request)["body"]
    for rejected in ("theirs", "all", True):
        invalid = deepcopy(request)
        cast(dict[str, Any], invalid)["body"]["filter"] = {**body["filter"], "author": rejected}
        with pytest.raises(ProtocolValueError):
            validate_schema_instance("control-request", "2.9.0", invalid)
