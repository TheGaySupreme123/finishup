#!/usr/bin/env python3
"""Generate immutable service-control schemas for repository authority."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Final, cast

from finishup.protocol.canonical import canonical_encode

_ROOT: Final = Path(__file__).resolve().parents[1]
_SERVICE: Final = _ROOT / "schemas" / "service"
_PRIVACY_POLICY: Final = "https://schemas.yoetz.dev/0.1/privacy/privacy-policy-1.0.0.schema.json"
_DIGEST: Final[dict[str, Any]] = {
    "maxLength": 71,
    "minLength": 71,
    "pattern": "^sha256:[0-9a-f]{64}$",
    "type": "string",
}
_COMMITMENT: Final[dict[str, Any]] = {
    "maxLength": 76,
    "minLength": 76,
    "pattern": "^hmac-sha256:[0-9a-f]{64}$",
    "type": "string",
}
_ORDINARY_CONTENT_CAPTURE_PROFILES: Final = (
    "claude-code-ordinary-observation-v1",
    "cursor-ordinary-observation-v1",
)
_MAX_SAFE_INTEGER: Final = 9_007_199_254_740_991
_OBSERVATION_TIMESTAMP: Final[dict[str, Any]] = {
    "maxLength": 24,
    "minLength": 24,
    "pattern": r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$",
    "type": "string",
}
_OBSERVATION_TOKEN: Final[dict[str, Any]] = {
    "maxLength": 128,
    "minLength": 1,
    "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$",
    "type": "string",
}


def _load(name: str) -> dict[str, Any]:
    return json.loads((_SERVICE / f"{name}-1.0.0.schema.json").read_text(encoding="utf-8"))


def _with_id(name: str, version: str, document: dict[str, Any]) -> dict[str, Any]:
    generated = copy.deepcopy(document)
    generated["$id"] = f"https://schemas.yoetz.dev/0.1/service/{name}-{version}.schema.json"
    return generated


def _hello() -> dict[str, Any]:
    generated = _with_id("control-hello", "2.0.0", _load("control-hello"))
    generated["properties"]["workspace_locator"] = {
        "additionalProperties": False,
        "properties": {
            "path": {
                "maxLength": 8192,
                "minLength": 1,
                "pattern": "^/[^\\u0000\\r\\n]*$",
                "type": "string",
            },
            "schema_version": {"const": "1.0.0"},
        },
        "required": ["schema_version", "path"],
        "type": "object",
    }
    generated["properties"]["presentation_context"] = {
        "additionalProperties": False,
        "properties": {
            "output_is_controlling_tty": {"type": "boolean"},
            "render_mode": {
                "enum": ["human_readable", "machine_readable"],
                "type": "string",
            },
        },
        "required": ["render_mode", "output_is_controlling_tty"],
        "type": "object",
    }
    return generated


def _request() -> dict[str, Any]:
    generated = _with_id("control-request", "2.0.0", _load("control-request"))
    definitions = generated["$defs"]
    # Domain source identities are structural tokens and the hook mapper deliberately prefixes
    # them with ``hook:``. The legacy schema token omitted the admitted colon.
    definitions["observation_envelope"]["properties"]["source_identity"]["pattern"] = (
        "^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$"
    )
    definitions["observation_content_chunk"] = {
        "additionalProperties": False,
        "properties": {
            "content_kind": {
                "enum": [
                    "visible_user_message",
                    "visible_assistant_message",
                    "visible_subagent_message",
                    "tool_input",
                    "tool_output",
                    "changed_file",
                    "workspace_diff",
                    "approved_check_output",
                    "unsupported_visible_payload",
                    "workspace_locator",
                ],
                "type": "string",
            },
            "correlation_identity": {
                "maxLength": 128,
                "minLength": 1,
                "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$",
                "type": "string",
            },
            "source_commitment": {
                "maxLength": 76,
                "minLength": 76,
                "pattern": "^hmac-sha256:[0-9a-f]{64}$",
                "type": "string",
            },
            "media_type": {
                "maxLength": 128,
                "minLength": 3,
                "pattern": "^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$",
                "type": "string",
            },
            "part_index": {"maximum": 15, "minimum": 0, "type": "integer"},
            "part_count": {"maximum": 16, "minimum": 1, "type": "integer"},
            "content_b64": {
                "maxLength": 699052,
                "minLength": 4,
                "pattern": (
                    "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/][AQgw]==|"
                    "[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=)?$"
                ),
                "type": "string",
            },
            "redacted": {"type": "boolean"},
        },
        "required": [
            "content_kind",
            "correlation_identity",
            "source_commitment",
            "media_type",
            "part_index",
            "part_count",
            "content_b64",
            "redacted",
        ],
        "type": "object",
    }
    definitions["observation_ingest_body"] = {
        "additionalProperties": False,
        "properties": {
            "codex_session_id": {
                "maxLength": 128,
                "minLength": 1,
                "pattern": "^[^/\\\\\\u0000]+$",
                "type": "string",
            },
            "content_chunks": {
                "items": {"$ref": "#/$defs/observation_content_chunk"},
                "maxItems": 16,
                "minItems": 1,
                "type": "array",
            },
            "envelope": {"$ref": "#/$defs/observation_envelope"},
        },
        "required": ["codex_session_id", "envelope"],
        "type": "object",
    }
    legacy_setup = definitions["privacy_get_setup_body"]
    definitions["privacy_get_setup_body"] = {
        "oneOf": [
            legacy_setup,
            {
                "additionalProperties": False,
                "properties": {"schema_version": {"const": "2.0.0"}},
                "required": ["schema_version"],
                "type": "object",
            },
        ]
    }
    legacy_proposal = definitions["privacy_propose_policy_body"]
    definitions["privacy_propose_policy_body"] = {
        "oneOf": [
            legacy_proposal,
            {
                "additionalProperties": False,
                "properties": {
                    "authority_digest": copy.deepcopy(_DIGEST),
                    "candidate_policy": {"$ref": _PRIVACY_POLICY},
                    "schema_version": {"const": "2.0.0"},
                },
                "required": ["schema_version", "authority_digest", "candidate_policy"],
                "type": "object",
            },
        ]
    }
    return generated


def _setup_result() -> dict[str, Any]:
    return {
        "additionalProperties": False,
        "properties": {
            "allowed_blocked_examples": {
                "items": {
                    "additionalProperties": False,
                    "properties": {
                        "allowed": {"type": "boolean"},
                        "code": {
                            "maxLength": 64,
                            "minLength": 1,
                            "pattern": "^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$",
                            "type": "string",
                        },
                    },
                    "required": ["code", "allowed"],
                    "type": "object",
                },
                "maxItems": 16,
                "type": "array",
                "uniqueItems": True,
            },
            "authority_digest": copy.deepcopy(_DIGEST),
            "bound_scope": {
                "allOf": [
                    {"$ref": f"{_PRIVACY_POLICY}#/$defs/authorization_scope"},
                    {
                        "properties": {"kind": {"const": "workspace"}},
                        "required": ["kind"],
                        "type": "object",
                    },
                ]
            },
            "channel_choices": {
                "items": {
                    "additionalProperties": False,
                    "properties": {
                        "capability_state": {
                            "enum": ["available", "unsupported"],
                            "type": "string",
                        },
                        "channel": {"$ref": f"{_PRIVACY_POLICY}#/$defs/egress_channel"},
                        "enabled": {"type": "boolean"},
                    },
                    "required": ["channel", "enabled", "capability_state"],
                    "type": "object",
                },
                "maxItems": 8,
                "type": "array",
                "uniqueItems": True,
            },
            "composed_policy": {"$ref": _PRIVACY_POLICY},
            "grant_state": {"enum": ["granted", "missing"], "type": "string"},
            "migration_state": {
                "enum": [
                    "not_applicable",
                    "legacy_route_available",
                    "first_repository_available",
                    "consumed",
                ],
                "type": "string",
            },
            "never_send_editable": {"const": False},
            "privacy_projection": {
                "$ref": (
                    "https://schemas.yoetz.dev/0.1/common/"
                    "operation-result-1.0.0.schema.json#/$defs/privacy_projection"
                )
            },
            "recipes": {
                "items": {
                    "additionalProperties": False,
                    "properties": {
                        "privacy_profile": {"$ref": f"{_PRIVACY_POLICY}#/$defs/privacy_profile"},
                        "recipe": {
                            "enum": [
                                "private",
                                "metadata_only",
                                "assisted_review",
                                "expanded_review",
                                "custom",
                            ],
                            "type": "string",
                        },
                        "review_context_profile": {
                            "$ref": f"{_PRIVACY_POLICY}#/$defs/review_context_profile"
                        },
                        "review_selection": {
                            "$ref": f"{_PRIVACY_POLICY}#/$defs/review_selection_policy"
                        },
                    },
                    "required": [
                        "recipe",
                        "privacy_profile",
                        "review_context_profile",
                        "review_selection",
                    ],
                    "type": "object",
                },
                "maxItems": 5,
                "type": "array",
                "uniqueItems": True,
            },
            "schema_version": {"const": "2.0.0"},
        },
        "required": [
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
        ],
        "type": "object",
    }


def _result() -> dict[str, Any]:
    generated = _with_id("control-result", "2.0.0", _load("control-result"))
    definitions = generated["$defs"]
    # The ready observation handler returns the bounded domain result directly. The legacy
    # request/status wrapper was replaced when routing ownership moved to the service coordinator.
    definitions["observation_ingest_body"] = copy.deepcopy(definitions["observation_ingest_result"])
    definitions["privacy_get_setup_body"] = {
        "oneOf": [definitions["privacy_get_setup_body"], _setup_result()]
    }
    legacy_proposal = definitions["privacy_propose_policy_body"]
    v2_proposal = copy.deepcopy(legacy_proposal)
    for branch in v2_proposal["oneOf"]:
        branch["properties"]["schema_version"] = {"const": "2.0.0"}
    definitions["privacy_propose_policy_body"] = {
        "oneOf": [*legacy_proposal["oneOf"], *v2_proposal["oneOf"]]
    }
    return generated


def _cursor_request() -> dict[str, Any]:
    generated = _with_id("control-request", "2.1.0", _request())
    envelope = generated["$defs"]["observation_envelope"]
    envelope["properties"]["source"]["enum"].append("cursor_hook")
    changed_paths_digest = copy.deepcopy(
        envelope["properties"]["structural_payload"]["properties"]["changed_paths_digest"]
    )
    envelope["properties"]["structural_payload"]["properties"]["changed_paths_digest"] = {
        "oneOf": [
            changed_paths_digest,
            {
                "maxLength": 76,
                "minLength": 76,
                "pattern": "^hmac-sha256:[0-9a-f]{64}$",
                "type": "string",
            },
        ]
    }
    # Cursor ingress admits three additional bounded structural tokens beside ``codex_version``.
    # ``structural_payload`` is ``additionalProperties: false``, so omitting them here would make
    # every Cursor observation that carries a Cursor/model identity undeliverable on the wire.
    # The domain validates exactly these three through its structural-token rule, whose token
    # alphabet admits ``:``; the wire pattern must not be narrower or the same class of
    # undeliverable observation returns for a colon-bearing model identity.
    for name in ("cursor_version", "model_id", "model_effort"):
        envelope["properties"]["structural_payload"]["properties"][name] = {
            "maxLength": 128,
            "minLength": 1,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$",
            "type": "string",
        }
    return generated


def _cursor_result() -> dict[str, Any]:
    generated = _with_id("control-result", "2.1.0", _result())
    source_coverage = generated["$defs"]["observation_status"]["properties"]["source_coverage"]
    source_coverage["properties"]["cursor_hook"] = {"type": "boolean"}
    return generated


def _claude_request() -> dict[str, Any]:
    generated = _with_id("control-request", "2.2.0", _cursor_request())
    generated["$defs"]["observation_envelope"]["properties"]["source"]["enum"].append("claude_hook")
    return generated


def _claude_result() -> dict[str, Any]:
    generated = _with_id("control-result", "2.2.0", _cursor_result())
    source_coverage = generated["$defs"]["observation_status"]["properties"]["source_coverage"]
    source_coverage["properties"]["claude_hook"] = {"type": "boolean"}
    return generated


def _replace_schema_ref(value: Any, old: str, new: str) -> None:
    if isinstance(value, dict):
        mapping = cast(dict[str, Any], value)
        for key, member in mapping.items():
            if key == "$ref" and member == old:
                mapping[key] = new
            else:
                _replace_schema_ref(member, old, new)
    elif isinstance(value, list):
        for member in cast(list[Any], value):
            _replace_schema_ref(member, old, new)


def _status_v23_request() -> dict[str, Any]:
    generated = _with_id("control-request", "2.3.0", _claude_request())
    _replace_schema_ref(
        generated,
        "https://schemas.yoetz.dev/0.1/operations/status-request-1.0.0.schema.json",
        "https://schemas.yoetz.dev/0.1/operations/status-request-1.1.0.schema.json",
    )
    return generated


def _status_v23_result() -> dict[str, Any]:
    generated = _with_id("control-result", "2.3.0", _claude_result())
    _replace_schema_ref(
        generated,
        "https://schemas.yoetz.dev/0.1/operations/status-result-1.0.0.schema.json",
        "https://schemas.yoetz.dev/0.1/operations/status-result-1.1.0.schema.json",
    )
    return generated


def _claim_v24_request() -> dict[str, Any]:
    generated = _with_id("control-request", "2.4.0", _status_v23_request())
    # Serving-host identity is new to the current, unreleased control schema.
    # Keep released 1.0/2.0 bytes and earlier request versions unchanged.
    for branch in generated["oneOf"]:
        properties = branch.get("properties", {})
        if properties.get("method", {}).get("const") == "check":
            properties["host_profile"] = {
                "enum": ["generic", "codex", "claude", "cursor"],
                "type": "string",
            }
    # Host/profile pairing metadata is likewise new to the current schema.
    # Keep the local observation envelope's structural keys closed for every
    # released request version while allowing the issue #607 ingress contract
    # through the active 2.4 control path.
    structural_properties = generated["$defs"]["observation_envelope"]["properties"][
        "structural_payload"
    ]["properties"]
    structural_properties.update(
        {
            "pairing_mode": {
                "enum": ["paired", "post_only"],
                "type": "string",
            },
            "correlation_kind": {
                "enum": ["tool_call_id", "generation_id", "none"],
                "type": "string",
            },
            "generation_id": {
                "maxLength": 128,
                "minLength": 1,
                "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$",
                "type": "string",
            },
        }
    )
    _replace_schema_ref(
        generated,
        "https://schemas.yoetz.dev/0.1/operations/publish-work-request-1.0.0.schema.json",
        "https://schemas.yoetz.dev/0.1/operations/publish-work-request-1.1.0.schema.json",
    )

    def admit_policy_versions(value: Any) -> None:
        if isinstance(value, dict):
            mapping = cast(dict[str, Any], value)
            if mapping.get("$ref") == _PRIVACY_POLICY:
                mapping.pop("$ref")
                mapping["anyOf"] = [
                    {"$ref": _PRIVACY_POLICY},
                    {
                        "$ref": "https://schemas.yoetz.dev/0.1/privacy/privacy-policy-1.1.0.schema.json"
                    },
                ]
            else:
                for child in mapping.values():
                    admit_policy_versions(child)
        elif isinstance(value, list):
            for child in cast(list[Any], value):
                admit_policy_versions(child)

    admit_policy_versions(generated)
    # The ordinary native-host content arm is a new optional request member.
    # Keep the released and intermediate control schemas byte-identical: only
    # the current unreleased 2.4 request may carry this authorization-bound
    # profile selector.
    ingest = generated["$defs"]["observation_ingest_body"]
    ingest["properties"]["content_capture_profile"] = {
        "enum": list(_ORDINARY_CONTENT_CAPTURE_PROFILES),
        "type": "string",
    }
    return generated


def _capture_v25_request() -> dict[str, Any]:
    """Append the authenticated native capture handoff to the active 2.4 control wire."""

    generated = _with_id("control-request", "2.5.0", _claim_v24_request())
    ingest = generated["$defs"]["observation_ingest_body"]
    # Native hook content is staged before the FIFO structural request.  Keep this opt-in marker
    # outside the frozen 2.4 schema and accept only the literal true arm; ordinary structural
    # requests omit it and retain the domain model's false default.
    ingest["properties"]["capture_only"] = {"const": True}
    # The capture lane is intentionally narrower than ordinary observation ingest.  Keep the
    # discriminator and the authorization-bound payload in one schema branch so validation cannot
    # admit a capture marker with an empty chunk set, an unknown profile, or a cross-host source.
    ingest["oneOf"] = [
        {"not": {"required": ["capture_only"]}},
        {
            "properties": {
                "capture_only": {"const": True},
                "content_capture_profile": {"const": "claude-code-ordinary-observation-v1"},
                "content_chunks": {"minItems": 1},
                "envelope": {
                    "properties": {"source": {"const": "claude_hook"}},
                    "required": ["source"],
                },
            },
            "required": ["capture_only", "content_capture_profile", "content_chunks"],
        },
        {
            "properties": {
                "capture_only": {"const": True},
                "content_capture_profile": {"const": "cursor-ordinary-observation-v1"},
                "content_chunks": {"minItems": 1},
                "envelope": {
                    "properties": {"source": {"const": "cursor_hook"}},
                    "required": ["source"],
                },
            },
            "required": ["capture_only", "content_capture_profile", "content_chunks"],
        },
        {
            "not": {"required": ["content_capture_profile"]},
            "properties": {
                "capture_only": {"const": True},
                "content_chunks": {"minItems": 1},
                "envelope": {
                    "properties": {"source": {"const": "codex_hook"}},
                    "required": ["source"],
                },
            },
            # Codex's native hook arm is authorized by the existing structural
            # observation grant. It is intentionally profile-less: adding a
            # public Codex profile would create a second consent vocabulary.
            "required": ["capture_only", "content_chunks"],
        },
    ]
    return generated


def _semantic_provenance_v24_result() -> dict[str, Any]:
    generated = _with_id("control-result", "2.4.0", _status_v23_result())
    for old, new in (
        ("check-result-1.0.0", "check-result-1.1.0"),
        ("receipt-result-1.0.0", "receipt-result-1.1.0"),
        ("status-result-1.1.0", "status-result-1.2.0"),
    ):
        _replace_schema_ref(
            generated,
            f"https://schemas.yoetz.dev/0.1/operations/{old}.schema.json",
            f"https://schemas.yoetz.dev/0.1/operations/{new}.schema.json",
        )
    _replace_schema_ref(
        generated,
        _PRIVACY_POLICY,
        "https://schemas.yoetz.dev/0.1/privacy/privacy-policy-1.1.0.schema.json",
    )
    return generated


def _semantic_provenance_v26_result() -> dict[str, Any]:
    """Point the active control result at the current workflow result contracts.

    Control-result 2.4 and 2.5 are released compatibility documents and retain their historical
    result references. The active 2.6 envelope must follow the current check, receipt, and status
    outputs so subscription-runtime evidence remains valid through the local control channel.
    """

    generated = _with_id("control-result", "2.6.0", _semantic_provenance_v24_result())
    for old, new in (
        ("check-result-1.1.0", "check-result-1.2.0"),
        ("receipt-result-1.1.0", "receipt-result-1.2.0"),
        ("status-result-1.2.0", "status-result-1.3.0"),
    ):
        _replace_schema_ref(
            generated,
            f"https://schemas.yoetz.dev/0.1/operations/{old}.schema.json",
            f"https://schemas.yoetz.dev/0.1/operations/{new}.schema.json",
        )
    return generated


def _selection_runtime_v26_result() -> dict[str, Any]:
    """Add the bounded optional selection projection to the new result wire.

    The observation status projection was added after the frozen 2.5 result contract.
    Keep released result bytes unchanged and attach the optional, structural-only
    projection to the new 2.6 result schema.  The nested maps are closed to the counters and
    opaque commitments emitted by the local store; they cannot become a content carrier.
    """

    generated = _semantic_provenance_v26_result()
    definitions = generated["$defs"]

    integer = {"maximum": _MAX_SAFE_INTEGER, "minimum": 0, "type": "integer"}
    positive_integer = {"maximum": _MAX_SAFE_INTEGER, "minimum": 1, "type": "integer"}
    nullable_timestamp = {"anyOf": [{"type": "null"}, copy.deepcopy(_OBSERVATION_TIMESTAMP)]}
    nullable_token = {"anyOf": [{"type": "null"}, copy.deepcopy(_OBSERVATION_TOKEN)]}
    nullable_commitment = {"anyOf": [{"type": "null"}, copy.deepcopy(_DIGEST)]}
    nullable_session_commitment = {"anyOf": [{"type": "null"}, copy.deepcopy(_COMMITMENT)]}

    definitions["observation_capture_backlog_route"] = {
        "additionalProperties": False,
        "properties": {
            "count": copy.deepcopy(integer),
            "byte_count": copy.deepcopy(integer),
            "oldest_receipt_time": copy.deepcopy(nullable_timestamp),
            "observed_at": copy.deepcopy(_OBSERVATION_TIMESTAMP),
            "reservation_count": {"maximum": 512, "minimum": 0, "type": "integer"},
            "reservation_unknown": {"type": "boolean"},
        },
        "required": [
            "count",
            "byte_count",
            "oldest_receipt_time",
            "observed_at",
            "reservation_count",
            "reservation_unknown",
        ],
        "type": "object",
    }
    definitions["observation_capture_backlog"] = {
        "additionalProperties": False,
        "properties": {
            "capture_backlog_scope": {"enum": ["unknown", "partial"], "type": "string"},
            "route_count": {"maximum": 256, "minimum": 0, "type": "integer"},
            "count": copy.deepcopy(integer),
            "byte_count": copy.deepcopy(integer),
            "oldest_receipt_time": copy.deepcopy(nullable_timestamp),
            "observed_at": copy.deepcopy(nullable_timestamp),
            "reservation_count": {"maximum": 512, "minimum": 0, "type": "integer"},
            "reserved_byte_count": copy.deepcopy(integer),
            "reservation_unknown": {"type": "boolean"},
            "routes": {
                "additionalProperties": {"$ref": "#/$defs/observation_capture_backlog_route"},
                "maxProperties": 256,
                "propertyNames": copy.deepcopy(_OBSERVATION_TOKEN),
                "type": "object",
            },
        },
        "required": [
            "capture_backlog_scope",
            "route_count",
            "count",
            "byte_count",
            "oldest_receipt_time",
            "observed_at",
            "reservation_count",
            "reserved_byte_count",
            "reservation_unknown",
            "routes",
        ],
        "type": "object",
    }
    definitions["observation_selection_loss_route"] = {
        "additionalProperties": False,
        "properties": {
            "selection_task_id": nullable_token,
            "selection_session_id": nullable_token,
            "selection_writer_id": nullable_token,
            "selection_authority_generation": nullable_commitment,
        },
        "required": [
            "selection_task_id",
            "selection_session_id",
            "selection_writer_id",
            "selection_authority_generation",
        ],
        "type": "object",
    }
    definitions["observation_selection_loss_range"] = {
        "additionalProperties": False,
        "properties": {
            "lane": copy.deepcopy(_DIGEST),
            "source": {
                "enum": ["claude_hook", "codex_hook", "codex_session_stream", "cursor_hook"],
                "type": "string",
            },
            "session": copy.deepcopy(_COMMITMENT),
            "source_generation": copy.deepcopy(positive_integer),
            "route": {"$ref": "#/$defs/observation_selection_loss_route"},
            "first_identity": copy.deepcopy(_OBSERVATION_TOKEN),
            "last_identity": copy.deepcopy(_OBSERVATION_TOKEN),
            "first_position": copy.deepcopy(integer),
            "last_position": copy.deepcopy(integer),
            "count": copy.deepcopy(positive_integer),
            "identity_extent": {"const": "bounded_range", "type": "string"},
        },
        "required": [
            "lane",
            "source",
            "session",
            "source_generation",
            "route",
            "first_identity",
            "last_identity",
            "first_position",
            "last_position",
            "count",
            "identity_extent",
        ],
        "type": "object",
    }
    definitions["observation_selection_accounting"] = {
        "additionalProperties": False,
        "properties": {
            "observed_count": copy.deepcopy(integer),
            "accounting_scope": {
                "const": "locally_ingested_since_selection_upgrade",
                "type": "string",
            },
            "admitted_input_count": copy.deepcopy(integer),
            "delivered_input_count": copy.deepcopy(integer),
            "summarized_input_count": copy.deepcopy(integer),
            "intentionally_omitted_input_count": copy.deepcopy(integer),
            "check_selection": {"const": "reported_by_each_check", "type": "string"},
            "summary_record_count": copy.deepcopy(integer),
            "buffered_input_count": copy.deepcopy(integer),
            "pending_attempt_count": copy.deepcopy(integer),
            "buffered_successful_call_count": copy.deepcopy(integer),
            "unrecoverable_input_count": copy.deepcopy(integer),
            "loss_identity_commitment": copy.deepcopy(nullable_commitment),
            "loss_ranges": {
                "items": {"$ref": "#/$defs/observation_selection_loss_range"},
                "maxItems": 64,
                "type": "array",
            },
            "loss_identity_list_complete": {"const": False, "type": "boolean"},
            "selection_epoch": copy.deepcopy(integer),
        },
        "required": [
            "observed_count",
            "accounting_scope",
            "admitted_input_count",
            "delivered_input_count",
            "summarized_input_count",
            "intentionally_omitted_input_count",
            "check_selection",
            "summary_record_count",
            "buffered_input_count",
            "pending_attempt_count",
            "buffered_successful_call_count",
            "unrecoverable_input_count",
            "loss_identity_commitment",
            "loss_ranges",
            "loss_identity_list_complete",
            "selection_epoch",
        ],
        "type": "object",
    }
    definitions["observation_selection_runtime"] = {
        "additionalProperties": False,
        "properties": {
            "selected_mode": {"enum": ["focused", "detailed"], "type": "string"},
            "effective_mode": {"enum": ["focused", "detailed"], "type": "string"},
            "selected_capacity": {"enum": [512, 2048, 8192], "type": "integer"},
            "effective_capacity": {"enum": [512, 2048, 8192], "type": "integer"},
            "selection_origin": {
                "enum": ["session", "workspace", "configured", "default"],
                "type": "string",
            },
            "selection_expires_at": copy.deepcopy(nullable_timestamp),
            "pressure_state": {
                "enum": ["healthy", "rising", "high", "hard_limit"],
                "type": "string",
            },
            "pressure_transition_identity": copy.deepcopy(nullable_token),
            "content_allowed": {"type": "boolean"},
            "admission_allowed": {"type": "boolean"},
            "queue_count": copy.deepcopy(integer),
            "queue_bytes": copy.deepcopy(integer),
            "state_bytes": copy.deepcopy(integer),
            "oldest_pending_age_ms": copy.deepcopy(integer),
            "pending_attempts": copy.deepcopy(integer),
            "pending_lifecycle_count": copy.deepcopy(integer),
            "capture_backlog": {"$ref": "#/$defs/observation_capture_backlog"},
            "protected_count_reserve": copy.deepcopy(integer),
            "protected_bytes_reserve": copy.deepcopy(integer),
            "session_fair_share": copy.deepcopy(integer),
            "session_fair_share_bytes": copy.deepcopy(integer),
            "accounting": {"$ref": "#/$defs/observation_selection_accounting"},
            "session_commitment": copy.deepcopy(nullable_session_commitment),
            "policy_version": copy.deepcopy(_OBSERVATION_TOKEN),
            "validation_status": copy.deepcopy(_OBSERVATION_TOKEN),
        },
        "required": [
            "selected_mode",
            "effective_mode",
            "selected_capacity",
            "effective_capacity",
            "selection_origin",
            "selection_expires_at",
            "pressure_state",
            "pressure_transition_identity",
            "content_allowed",
            "admission_allowed",
            "queue_count",
            "queue_bytes",
            "state_bytes",
            "oldest_pending_age_ms",
            "pending_attempts",
            "pending_lifecycle_count",
            "capture_backlog",
            "protected_count_reserve",
            "protected_bytes_reserve",
            "session_fair_share",
            "session_fair_share_bytes",
            "accounting",
            "session_commitment",
            "policy_version",
            "validation_status",
        ],
        "type": "object",
    }
    definitions["observation_status"]["properties"]["selection_runtime"] = {
        "$ref": "#/$defs/observation_selection_runtime"
    }
    return generated


def _documents() -> dict[Path, bytes]:
    documents = {
        ("control-hello", "2.0.0"): _hello(),
        ("control-hello-result", "2.0.0"): _with_id(
            "control-hello-result", "2.0.0", _load("control-hello-result")
        ),
        ("control-request", "2.0.0"): _request(),
        ("control-result", "2.0.0"): _result(),
        ("control-hello", "2.1.0"): _with_id("control-hello", "2.1.0", _hello()),
        ("control-hello-result", "2.1.0"): _with_id(
            "control-hello-result",
            "2.1.0",
            _with_id("control-hello-result", "2.0.0", _load("control-hello-result")),
        ),
        ("control-request", "2.1.0"): _cursor_request(),
        ("control-result", "2.1.0"): _cursor_result(),
        ("control-hello", "2.2.0"): _with_id("control-hello", "2.2.0", _hello()),
        ("control-hello-result", "2.2.0"): _with_id(
            "control-hello-result",
            "2.2.0",
            _with_id("control-hello-result", "2.0.0", _load("control-hello-result")),
        ),
        ("control-request", "2.2.0"): _claude_request(),
        ("control-result", "2.2.0"): _claude_result(),
        ("control-hello", "2.3.0"): _with_id("control-hello", "2.3.0", _hello()),
        ("control-hello-result", "2.3.0"): _with_id(
            "control-hello-result",
            "2.3.0",
            _with_id("control-hello-result", "2.0.0", _load("control-hello-result")),
        ),
        ("control-request", "2.3.0"): _status_v23_request(),
        ("control-result", "2.3.0"): _status_v23_result(),
        ("control-hello", "2.4.0"): _with_id("control-hello", "2.4.0", _hello()),
        ("control-hello-result", "2.4.0"): _with_id(
            "control-hello-result",
            "2.4.0",
            _with_id("control-hello-result", "2.0.0", _load("control-hello-result")),
        ),
        ("control-request", "2.4.0"): _claim_v24_request(),
        ("control-result", "2.4.0"): _semantic_provenance_v24_result(),
        ("control-hello", "2.5.0"): _with_id("control-hello", "2.5.0", _hello()),
        ("control-hello-result", "2.5.0"): _with_id(
            "control-hello-result",
            "2.5.0",
            _with_id(
                "control-hello-result",
                "2.4.0",
                _with_id("control-hello-result", "2.0.0", _load("control-hello-result")),
            ),
        ),
        ("control-request", "2.5.0"): _capture_v25_request(),
        ("control-result", "2.5.0"): _with_id(
            "control-result", "2.5.0", _semantic_provenance_v24_result()
        ),
        ("control-hello", "2.6.0"): _with_id("control-hello", "2.6.0", _hello()),
        ("control-hello-result", "2.6.0"): _with_id(
            "control-hello-result",
            "2.6.0",
            _with_id("control-hello-result", "2.0.0", _load("control-hello-result")),
        ),
        ("control-request", "2.6.0"): _with_id("control-request", "2.6.0", _capture_v25_request()),
        ("control-result", "2.6.0"): _selection_runtime_v26_result(),
    }
    return {
        _SERVICE / f"{name}-{version}.schema.json": canonical_encode(document)
        for (name, version), document in documents.items()
    }


def _sync_manifest(documents: dict[Path, bytes], *, write: bool) -> list[Path]:
    manifest_path = _ROOT / "schemas" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    members = cast(list[dict[str, Any]], manifest["members"])
    by_path = {cast(str, member["path"]): member for member in members}
    owning_models = {
        "control-hello": "control hello wire helper",
        "control-hello-result": "control hello result wire helper",
        "control-request": "ControlRequest",
        "control-result": "ControlResult",
    }
    mismatches: list[Path] = []
    for path, payload in documents.items():
        relative = path.relative_to(_ROOT / "schemas").as_posix()
        name_and_version = path.name.removesuffix(".schema.json")
        name, version = name_and_version.rsplit("-", 1)
        expected = {
            "$id": f"https://schemas.yoetz.dev/0.1/{relative}",
            "artifact_role": "local-control",
            "byte_length": len(payload),
            "media_type": "application/schema+json",
            "owning_model": owning_models[name],
            "path": relative,
            "schema_kind": "request_result",
            "schema_version": version,
            "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
        }
        existing = by_path.get(relative)
        if existing != expected:
            mismatches.append(path.relative_to(_ROOT))
            if write:
                if existing is None:
                    members.append(expected)
                else:
                    existing.clear()
                    existing.update(expected)
    if write:
        members.sort(key=lambda member: cast(str, member["path"]).encode("ascii"))
        manifest_path.write_bytes(canonical_encode(manifest))
        return []
    return mismatches


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    documents = _documents()
    mismatches: list[Path] = []
    for path, expected in documents.items():
        if args.write:
            path.write_bytes(expected)
        elif not path.is_file() or path.read_bytes() != expected:
            mismatches.append(path.relative_to(_ROOT))
    mismatches.extend(_sync_manifest(documents, write=args.write))
    if mismatches:
        for path in mismatches:
            print(f"generated schema stale: {path}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
