"""Deterministic public JSON Schema generator and parity checker for the FinishUP protocol.

Generates and verifies the reviewable JSON Schema files for the public six-operation
request/result models, the read-only guidance tool, shared common values, durable event
payloads, configuration, findings,
receipts, privacy, local-control, and version-report contracts. This is a repository maintainer
tool, not runtime code: installed users never run it. It never imports application, adapter, CLI,
MCP, provider, key, storage, or package-resource modules; model discovery is an explicit ordered
registry, not module walking.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Final, cast

from pydantic import TypeAdapter
from pydantic_core import core_schema

from finishup.domain.review_guidance import ReviewGuidance
from finishup.domain.verification_coverage import VERIFICATION_EXPECTED_FROM
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.models import MAX_REVIEW_EXCERPTS

__all__ = [
    "SCHEMA_NAMESPACE",
    "SchemaDiff",
    "SchemaDocument",
    "build_schema_documents",
    "compare_tree",
    "main",
    "render_schema",
    "validate_schema_document",
    "write_tree",
]


# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

SCHEMA_NAMESPACE: Final = "https://schemas.yoetz.dev/0.1/"
_DRAFT_2020_12: Final = "https://json-schema.org/draft/2020-12/schema"
_SCHEMA_MEDIA_TYPE: Final = "application/schema+json"
_MAX_OUTPUT_BYTES: Final = 20_000_000
_MAX_GUIDANCE_DOCUMENT_BYTES: Final = 1_048_576
_MAX_GUIDANCE_SECTIONS: Final = 128


class SchemaGenerationError(Exception):
    """A bounded, traceback-free failure while building the frozen schema registry."""

    def __init__(self, reason: str, *, entries: tuple[str, ...] = ()) -> None:
        super().__init__(reason)
        self.reason = reason
        self.entries = entries


@dataclass(frozen=True, slots=True)
class SchemaDocument:
    schema_kind: str
    artifact_role: str
    schema_name: str
    schema_version: str
    schema_id: str
    relative_path: str
    canonical_digest: str
    schema_bytes: bytes
    json_schema: Mapping[str, JsonValue]


@dataclass(frozen=True, slots=True)
class SchemaDiff:
    missing: tuple[str, ...]
    extra: tuple[str, ...]
    changed: tuple[str, ...]

    @property
    def is_clean(self) -> bool:
        return not (self.missing or self.extra or self.changed)


# --------------------------------------------------------------------------
# Custom-type shims for schema generation only (no source-file changes)
# --------------------------------------------------------------------------


def _install_type_shims() -> None:
    """Teach pydantic how to introspect two hand-rolled immutable domain types.

    ``JsonObject`` (an immutable ``Mapping[str, JsonValue]``) and ``ControlError`` (a bounded
    exception with two typed attributes) are not pydantic-native. Rather than modify their owning
    modules, the generator attaches ``__get_pydantic_core_schema__`` to the already-imported class
    objects for the duration of this process only.
    """

    from finishup.domain.values import JsonObject
    from finishup.ports.control import ControlError

    def _json_object_schema(cls: type, source: type, handler: object) -> core_schema.CoreSchema:
        return core_schema.dict_schema(core_schema.str_schema(), core_schema.any_schema())

    def _control_error_schema(cls: type, source: type, handler: object) -> core_schema.CoreSchema:
        return core_schema.typed_dict_schema(
            {
                "reason": core_schema.typed_dict_field(core_schema.str_schema()),
                "retryable": core_schema.typed_dict_field(core_schema.bool_schema()),
                # Optional; present when the service already minted a diagnostic identity.
                "correlation_id": core_schema.typed_dict_field(
                    core_schema.str_schema(), required=False
                ),
            }
        )

    JsonObject.__get_pydantic_core_schema__ = classmethod(_json_object_schema)  # type: ignore[attr-defined]
    ControlError.__get_pydantic_core_schema__ = classmethod(_control_error_schema)  # type: ignore[attr-defined]


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _RegistryEntry:
    relative_path: str
    schema_name: str
    schema_version: str
    schema_kind: str
    artifact_role: str
    loader: Callable[[], object] | None
    """Zero-arg callable returning the Python type/type-alias to introspect via ``TypeAdapter``.

    ``None`` marks a registry entry whose owning Python type is not yet materialized by another
    build wave (tracked explicitly rather than guessed); ``build_schema_documents`` reports these
    as a bounded, named ``SchemaGenerationError`` instead of fabricating a schema.
    """


def _operation_result_schema() -> object:
    from finishup.protocol.models import OperationFailureModel

    return OperationFailureModel


def _version_manifest_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Update the reviewed closed version schema from current runtime inventory constants.

    The version report intentionally has a stronger, finite contract than Pydantic can infer from
    its tuple-backed runtime dataclass. Preserve that reviewed schema shape while regenerating the
    exact request/result version map and resource inventory cardinalities through this owning tool.
    """

    from finishup.version import build_version_manifest

    source = (
        Path(__file__).resolve().parent.parent
        / "schemas/version/version-manifest-1.0.0.schema.json"
    )
    try:
        document = cast(dict[str, JsonValue], json.loads(source.read_bytes()))
        definitions = cast(dict[str, JsonValue], document["$defs"])
        request_versions = cast(dict[str, JsonValue], definitions["request_result_schema_versions"])
        event_versions = cast(dict[str, JsonValue], definitions["event_schema_versions"])
        resource_counts = cast(dict[str, JsonValue], definitions["resource_counts"])
        resources = cast(dict[str, JsonValue], document["properties"])["resources"]
        if not isinstance(resources, dict):
            raise TypeError
    except (KeyError, OSError, TypeError, json.JSONDecodeError) as exc:
        raise SchemaGenerationError(
            "version_schema_template_invalid", entries=(entry.relative_path,)
        ) from exc

    # Bootstrap a newly versioned inventory schema from the released predecessor. The
    # owning ripple mirrors the enlarged inventory, then rebuilds this schema in the same
    # pass and verifies a fixed point before reporting success.
    destination = source.parents[1] / entry.relative_path
    if entry.schema_version == "2.3.0" and not destination.exists():
        document = _load_versioned_template(entry, "version/version-manifest-2.2.4.schema.json")
        cast(dict[str, JsonValue], document["properties"])["schema_version"] = {
            "const": entry.schema_version
        }
        return document

    manifest = build_version_manifest()
    version_pairs = dict(manifest.request_result_schema_versions)
    request_versions.clear()
    request_versions.update(
        cast(
            dict[str, JsonValue],
            {
                "additionalProperties": False,
                "maxProperties": len(version_pairs),
                "minProperties": len(version_pairs),
                "properties": {
                    name: {"const": version}
                    for name, version in sorted(
                        version_pairs.items(), key=lambda item: item[0].encode()
                    )
                },
                "required": sorted(version_pairs, key=str.encode),
                "type": "object",
            },
        )
    )
    event_pairs = dict(manifest.event_schema_versions)
    event_versions.clear()
    event_versions.update(
        cast(
            dict[str, JsonValue],
            {
                "additionalProperties": False,
                "maxProperties": len(event_pairs),
                "minProperties": len(event_pairs),
                "properties": {
                    name: {"const": version}
                    for name, version in sorted(
                        event_pairs.items(), key=lambda item: item[0].encode()
                    )
                },
                "required": sorted(event_pairs, key=str.encode),
                "type": "object",
            },
        )
    )

    counts = dict(manifest.resource_counts)
    count_properties: dict[str, JsonValue] = {
        name: {"const": value}
        for name, value in sorted(counts.items(), key=lambda item: item[0].encode())
    }
    resource_counts["properties"] = count_properties
    resource_counts["required"] = cast(list[JsonValue], sorted(counts, key=str.encode))
    total = int(counts["total"])
    resources["maxItems"] = total
    resources["oneOf"] = [{"maxItems": 0}, {"maxItems": total, "minItems": total}]
    properties = cast(dict[str, JsonValue], document["properties"])
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    document["title"] = f"Yoetz version manifest {entry.schema_version}"
    properties["schema_version"] = {"const": entry.schema_version}
    properties["policy_versions"] = {"const": list(manifest.policy_versions)}
    for field_name in (
        "application_id",
        "bundle_schema_version",
        "catalog_schema_version",
        "control_protocol_version",
        "egress_receipt_schema_version",
        "engine_version",
        "object_format_version",
        "privacy_classifier_ruleset_version",
        "privacy_policy_schema_version",
        "projection_version",
        "protocol_version",
    ):
        properties[field_name] = {"const": cast(JsonValue, getattr(manifest, field_name))}
    # Protocol 0.1 shipped as Yoetz and the product is now FinishUP (ADR-048). Released inventory
    # versions keep their frozen `yoetz` const; this one names the shipping distribution and still
    # admits a report from a pre-rename development build.
    properties["package_name"] = {"enum": ["finishup", "yoetz"], "type": "string"}
    return document


def _frozen_schema(
    entry: _RegistryEntry, *, error_reason: str = "frozen_schema_template_invalid"
) -> dict[str, JsonValue]:
    """Load a released schema byte model without deriving a replacement shape."""

    source = Path(__file__).resolve().parent.parent / "schemas" / entry.relative_path
    try:
        return cast(dict[str, JsonValue], json.loads(source.read_bytes()))
    except (OSError, TypeError, json.JSONDecodeError) as exc:
        raise SchemaGenerationError(error_reason, entries=(entry.relative_path,)) from exc


def _privacy_policy_v1_1_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Append fallback authorization without changing the released v1.0 contract."""

    document = _simple_versioned_schema(entry, "privacy/privacy-policy-1.0.0.schema.json", {})
    properties = cast(dict[str, JsonValue], document["properties"])
    properties["schema_version"] = {"const": "1.1.0"}
    definitions = cast(dict[str, dict[str, JsonValue]], document["$defs"])
    base = definitions["channel_policy_base"]
    cast(dict[str, JsonValue], base["properties"])["fallback_provider_binding"] = {
        "$ref": "#/$defs/provider_binding"
    }
    fallback_rule: JsonValue = {
        "if": {"required": ["fallback_provider_binding"]},
        "then": {
            "required": ["provider_binding"],
            "properties": {
                "provider_binding": {"properties": {"transport": {"const": "external"}}},
                "fallback_provider_binding": {"properties": {"transport": {"const": "external"}}},
            },
        },
    }
    cast(list[JsonValue], base["allOf"]).append(fallback_rule)
    disabled = cast(dict[str, JsonValue], cast(list[JsonValue], base["allOf"])[0])
    then = cast(dict[str, JsonValue], disabled["then"])
    then["not"] = {
        "anyOf": [{"required": ["provider_binding"]}, {"required": ["fallback_provider_binding"]}]
    }
    for name in ("crash_diagnostics", "update_checks", "capability_testing", "product_telemetry"):
        arm = cast(
            dict[str, JsonValue], cast(list[JsonValue], definitions[name + "_policy"]["allOf"])[1]
        )
        arm["not"] = {
            "anyOf": [
                {"required": ["provider_binding"]},
                {"required": ["fallback_provider_binding"]},
            ]
        }
    return document


# The agent-transcribed task statement (issue #908). JSON Schema bounds characters; the owning
# domain and request models also bound its UTF-8 encoding to the same 65,536 bytes.
_TASK_STATEMENT_SCHEMA: Final[dict[str, JsonValue]] = {
    "maxLength": 65536,
    "minLength": 1,
    "type": "string",
}


def _with_required_task_statement(
    entry: _RegistryEntry, source_relative_path: str, *, title: str | None = None
) -> dict[str, JsonValue]:
    """Copy one frozen event payload and require the task statement its new version carries.

    Each family's statement-bearing version exists only to carry the statement, so the field is
    required there and absent from every earlier version (issue #908).
    """

    document = _load_versioned_template(entry, source_relative_path)
    properties = cast(dict[str, JsonValue], document["properties"])
    properties["task_statement"] = dict(_TASK_STATEMENT_SCHEMA)
    required = cast(list[JsonValue], document.setdefault("required", []))
    if "task_statement" not in required:
        required.append("task_statement")
    if title is not None:
        document["title"] = f"{title} {entry.schema_version}"
    return document


# The statement-bearing versions of released families (issue #908). ``session_opened`` 1.2.0 is
# unreleased and carries the optional statement in place, so its existing branch already admits it.
_TASK_STATEMENT_EVENT_PAIRS: Final[tuple[tuple[str, str], ...]] = (
    ("session_resumed", "1.2.0"),
    ("plan_published", "1.1.0"),
    ("plan_revised", "1.1.0"),
)
# Role- and directory-bearing obligations (issue #1002): a new version of a released family that
# the unreleased event-draft 1.2.0 admits in place.
_OBLIGATION_EVENT_PAIRS: Final[tuple[tuple[str, str], ...]] = (
    ("obligation_published", "1.1.0"),
    # A conversation's review-mode switch (ADR-049) rides the same unreleased event draft.
    ("decision_recorded", "1.1.0"),
)


def _privacy_policy_v1_2_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Add the ``task_statement`` review section and lift the Expanded excerpt count.

    Goal-aware, Assisted and Expanded presets include the section from this version on;
    Structural never does, and Custom only when its owner lists it. A 1.1.0 document can never
    name the section, so an approval given before it existed is never read as covering the
    user's request (issue #908).

    ``max_excerpts`` is bounded by the protocol maximum instead of 16, and the Expanded preset uses
    it, so the unchanged byte budget binds; Assisted keeps 16 (issue #907 Phase 1b).
    """

    document = _simple_versioned_schema(entry, "privacy/privacy-policy-1.1.0.schema.json", {})
    document["title"] = f"Yoetz privacy policy {entry.schema_version}"
    properties = cast(dict[str, JsonValue], document["properties"])
    properties["schema_version"] = {"const": entry.schema_version}
    definitions = cast(dict[str, dict[str, JsonValue]], document["$defs"])
    section_enum = cast(list[JsonValue], definitions["review_section"]["enum"])
    section_enum.append("task_statement")
    section_enum.sort(key=lambda value: cast(str, value).encode("ascii"))
    selection_properties = cast(
        dict[str, JsonValue], definitions["review_selection_policy"]["properties"]
    )
    sections = cast(dict[str, JsonValue], selection_properties["sections"])
    sections["maxItems"] = len(section_enum)
    cast(dict[str, JsonValue], selection_properties["max_excerpts"])["maximum"] = (
        MAX_REVIEW_EXCERPTS
    )
    for rule in cast(list[JsonValue], document["allOf"]):
        if not isinstance(rule, dict):
            continue
        condition = rule.get("if")
        then = rule.get("then")
        if not isinstance(condition, dict) or not isinstance(then, dict):
            continue
        profile = cast(dict[str, JsonValue], condition.get("properties", {})).get(
            "review_context_profile"
        )
        if not isinstance(profile, dict) or profile.get("const") not in {
            "goal_aware",
            "assisted",
            "expanded",
        }:
            continue
        preset = cast(
            dict[str, JsonValue],
            cast(
                dict[str, JsonValue],
                cast(dict[str, JsonValue], then["properties"])["review_selection"],
            )["const"],
        )
        preset_sections = cast(list[JsonValue], preset["sections"])
        preset_sections.append("task_statement")
        preset_sections.sort(key=lambda value: cast(str, value).encode("ascii"))
        if profile.get("const") == "expanded":
            preset["max_excerpts"] = MAX_REVIEW_EXCERPTS
    # The owner opt-out for the low-confidence credential heuristic (issue #982). Optional, and
    # written only when ``disabled``, so every policy without it keeps its bytes and digest; an
    # absent field means ``enforced``. Older wire versions cannot carry it.
    properties["credential_heuristic"] = {"enum": ["disabled", "enforced"], "type": "string"}
    # How conversations start and whether an agent's switch to AI-powered review waits for the
    # owner (ADR-049). Optional and written only when set, so every policy without it keeps its
    # bytes and digest; absent means the released behaviour. Older wire versions cannot carry it.
    properties["conversation_review"] = {
        "enum": ["ai_powered", "local_agent_opt_in", "local_only", "local_owner_approval"],
        "type": "string",
    }
    # Directories outside the workspace the owner admitted for read-only task inputs (issue
    # #1082). Optional and written only when non-empty, so every policy without it keeps its
    # bytes and digest. Older wire versions cannot carry it. The runtime additionally refuses
    # hidden components and system trees such as /etc, /proc and /dev.
    properties["admitted_input_roots"] = {
        "items": {
            "maxLength": 190,
            "pattern": "^(/[A-Za-z0-9_+@-][A-Za-z0-9._+@-]{0,127}){1,16}$",
            "type": "string",
        },
        "maxItems": 8,
        "minItems": 1,
        "type": "array",
        "uniqueItems": True,
    }
    return document


def _add_task_statement_to_outbound_case(document: dict[str, JsonValue]) -> None:
    """Carry the source-labelled task statement section in outbound-case 1.2.0 (issue #908).

    Applied on top of the #905 prior-findings additions, so the one unreleased 1.2.0 contract
    requires both ``prior_finding_refs`` and ``task_statement_item_ids``. It also carries the
    #907 Phase 1b excerpt count.
    """

    definitions = cast(dict[str, dict[str, JsonValue]], document["$defs"])
    item_properties = cast(dict[str, JsonValue], definitions["content_item"]["properties"])
    section = cast(dict[str, JsonValue], item_properties["section"])
    section_enum = cast(list[JsonValue], section["enum"])
    section_enum.append("task_statement")
    section_enum.sort(key=lambda value: cast(str, value).encode("ascii"))
    item_properties["label"] = {
        "enum": [
            "agent plan (the agent's own summary)",
            "task statement: what the user asked for; the source field says who supplied the text",
        ],
        "type": "string",
    }
    definitions["item_id_list_1"] = {
        "items": {"$ref": "#/$defs/item_id"},
        "maxItems": 1,
        "minItems": 0,
        "type": "array",
        "uniqueItems": True,
    }
    packet = definitions["review_packet"]
    packet_properties = cast(dict[str, JsonValue], packet["properties"])
    packet_properties["task_statement_item_ids"] = {"$ref": "#/$defs/item_id_list_1"}
    cast(list[JsonValue], packet["required"]).append("task_statement_item_ids")
    # The excerpt count follows the protocol maximum, and the case keeps room for the other
    # sections it had beside 16 excerpts (issue #907 Phase 1b).
    excerpts = cast(dict[str, JsonValue], packet_properties["targeted_excerpts"])
    excerpts["maxItems"] = MAX_REVIEW_EXCERPTS
    properties = cast(dict[str, JsonValue], document["properties"])
    content_items = cast(dict[str, JsonValue], properties["content_items"])
    content_items["maxItems"] = cast(int, content_items["maxItems"]) + MAX_REVIEW_EXCERPTS - 16


def _privacy_policy_v1_3_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Let a channel's ``max_bytes`` reach the sized reviewer exchange bound (#1118).

    Identical to 1.2.0 except that ``max_bytes`` admits up to 524,288 bytes
    (``MAX_SIZED_EXCHANGE_BYTES``, the outbound-document bound ``MAX_EGRESS_CASE_BYTES``), so the
    Codex subscription route sized to its model's context can use its whole exchange budget. A
    policy whose ceilings fit 262,144 bytes keeps its older wire version and bytes.
    """

    document = _simple_versioned_schema(entry, "privacy/privacy-policy-1.2.0.schema.json", {})
    document["title"] = f"Yoetz privacy policy {entry.schema_version}"
    properties = cast(dict[str, JsonValue], document["properties"])
    properties["schema_version"] = {"const": entry.schema_version}
    definitions = cast(dict[str, dict[str, JsonValue]], document["$defs"])
    definitions["max_524288_decimal"] = {
        "$ref": SCHEMA_NAMESPACE
        + "privacy/outbound-case-1.0.0.schema.json#/$defs/max_524288_decimal"
    }
    base = definitions["channel_policy_base"]
    cast(dict[str, JsonValue], base["properties"])["max_bytes"] = {
        "$ref": "#/$defs/max_524288_decimal"
    }
    return document


def _admit_privacy_policy_v1_2(document: dict[str, JsonValue]) -> dict[str, JsonValue]:
    """Let the unreleased 2.9 control boundary carry the 1.2.0 privacy-policy wire (issue #908).

    Every privacy-policy document the boundary carries may be the 1.2.0 wire that names the
    ``task_statement`` review section; a 1.1.0 policy stays valid unchanged, and recipe review
    selections use the 1.2.0 section vocabulary (a superset of 1.0.0).
    """

    policy_v11 = SCHEMA_NAMESPACE + "privacy/privacy-policy-1.1.0.schema.json"
    policy_v12 = SCHEMA_NAMESPACE + "privacy/privacy-policy-1.2.0.schema.json"
    policy_v13 = SCHEMA_NAMESPACE + "privacy/privacy-policy-1.3.0.schema.json"
    replacements = {
        SCHEMA_NAMESPACE
        + "privacy/privacy-policy-1.0.0.schema.json#/$defs/review_selection_policy": policy_v12
        + "#/$defs/review_selection_policy",
    }

    def rewrite(value: JsonValue, *, union_member: bool = False) -> JsonValue:
        if isinstance(value, list):
            items = [rewrite(item, union_member=True) for item in value]
            refs = [item.get("$ref") for item in items if isinstance(item, dict)]
            if policy_v11 in refs and policy_v12 not in refs:
                # A union that already admits the 1.1.0 document also admits 1.2.0 and 1.3.0.
                items.append({"$ref": policy_v12})
                items.append({"$ref": policy_v13})
            return cast(JsonValue, items)
        if isinstance(value, dict):
            ref = value.get("$ref")
            if isinstance(ref, str) and ref in replacements:
                return cast(JsonValue, {**value, "$ref": replacements[ref]})
            if ref == policy_v11 and len(value) == 1 and not union_member:
                # A lone 1.1.0 policy document becomes either wire version.
                return cast(
                    JsonValue,
                    {"anyOf": [{"$ref": policy_v11}, {"$ref": policy_v12}, {"$ref": policy_v13}]},
                )
            return cast(JsonValue, {key: rewrite(item) for key, item in value.items()})
        return value

    return cast(dict[str, JsonValue], rewrite(document))


def _frozen_version_manifest_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Preserve the released v2.0 version report while newer reports append."""

    return _frozen_schema(entry, error_reason="version_schema_template_invalid")


def _routine_read_summary_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Render the local, source-accounting summary envelope contract.

    The summary is intentionally an observation envelope rather than a task-ledger
    event payload.  Its member list binds every source identity and cursor that the
    summary advances over; content and caller prose have no place in this schema.
    """

    token = {
        "maxLength": 128,
        "minLength": 1,
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/+-]*$",
        "type": "string",
    }
    digest = {
        "maxLength": 71,
        "minLength": 71,
        "pattern": "^sha256:[0-9a-f]{64}$",
        "type": "string",
    }
    task_id = {
        "maxLength": 40,
        "minLength": 40,
        "pattern": r"^tsk_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        "type": "string",
    }
    session_id = {
        "maxLength": 40,
        "minLength": 40,
        "pattern": r"^ses_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        "type": "string",
    }
    writer_id = {
        "maxLength": 40,
        "minLength": 40,
        "pattern": r"^wri_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        "type": "string",
    }
    commitment = {
        "maxLength": 76,
        "minLength": 76,
        "pattern": "^hmac-sha256:[0-9a-f]{64}$",
        "type": "string",
    }
    timestamp = {
        "format": "date-time",
        "pattern": r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$",
        "type": "string",
    }
    cursor = {
        "additionalProperties": False,
        "properties": {
            "source_generation": {
                "maximum": 9_007_199_254_740_991,
                "minimum": 1,
                "type": "integer",
            },
            "byte_position": {"maximum": 9_007_199_254_740_991, "minimum": 0, "type": "integer"},
            "event_position": {"maximum": 9_007_199_254_740_991, "minimum": 0, "type": "integer"},
            "last_source_commitment": commitment,
            "mapping_version": token,
        },
        "required": [
            "byte_position",
            "event_position",
            "last_source_commitment",
            "mapping_version",
            "source_generation",
        ],
        "type": "object",
    }
    member = {
        "additionalProperties": False,
        "properties": {
            "source_identity": token,
            "cursor": {"$ref": "#/$defs/cursor"},
            "tool_call_id": {"oneOf": [token, {"type": "null"}]},
            "phase": {"enum": ["post", "pre"], "type": "string"},
            "receipt_time": timestamp,
            "subject_state_digest": {"oneOf": [digest, {"type": "null"}]},
        },
        "required": [
            "cursor",
            "phase",
            "receipt_time",
            "source_identity",
            "subject_state_digest",
            "tool_call_id",
        ],
        "type": "object",
    }
    structural_payload = {
        "additionalProperties": False,
        "properties": {
            "action": {"const": "routine_read_summary", "type": "string"},
            "summary_count": {"maximum": 16, "minimum": 1, "type": "integer"},
            "input_count": {"maximum": 32, "minimum": 1, "type": "integer"},
            "member_digest": digest,
            "fence": digest,
            "provenance": {"const": "routine_success_summary", "type": "string"},
            "summary_schema": {
                "const": "yoetz.observation-routine-read-summary/1.0.0",
                "type": "string",
            },
            "selection_policy_version": {"const": "obs-selection/1.0.0", "type": "string"},
            "content_scope": {"const": "structural_only", "type": "string"},
            "coverage_gaps": {
                "items": {
                    "enum": ["content_unselected", "observation_input_loss"],
                    "type": "string",
                },
                "maxItems": 2,
                "minItems": 0,
                "type": "array",
                "uniqueItems": True,
            },
            "members": {
                "items": {"$ref": "#/$defs/member"},
                "maxItems": 32,
                "minItems": 1,
                "type": "array",
            },
            "selection_task_id": task_id,
            "selection_session_id": session_id,
            "selection_writer_id": writer_id,
            "selection_authority_generation": digest,
        },
        "required": [
            "action",
            "content_scope",
            "coverage_gaps",
            "fence",
            "input_count",
            "member_digest",
            "members",
            "provenance",
            "selection_policy_version",
            "summary_count",
            "summary_schema",
            "selection_task_id",
            "selection_session_id",
            "selection_writer_id",
            "selection_authority_generation",
        ],
        "type": "object",
    }
    document: dict[str, object] = {
        "$id": SCHEMA_NAMESPACE + entry.relative_path,
        "$schema": _DRAFT_2020_12,
        "additionalProperties": False,
        "$defs": {
            "commitment": commitment,
            "cursor": cursor,
            "digest": digest,
            "member": member,
            "timestamp": timestamp,
            "token": token,
        },
        "properties": {
            "event_kind": {"const": "RoutineReadSummary", "type": "string"},
            "session_commitment": commitment,
            "source": {
                "enum": ["claude_hook", "codex_hook", "codex_session_stream", "cursor_hook"],
                "type": "string",
            },
            "source_identity": {"pattern": "^summary:[0-9a-f]{64}$", "type": "string"},
            "cursor": {"$ref": "#/$defs/cursor"},
            "receipt_time": timestamp,
            "structural_payload": structural_payload,
            "content_object_refs": {"maxItems": 0, "type": "array"},
            "gap_codes": {"maxItems": 0, "type": "array"},
        },
        "required": [
            "content_object_refs",
            "cursor",
            "event_kind",
            "gap_codes",
            "receipt_time",
            "session_commitment",
            "source",
            "source_identity",
            "structural_payload",
        ],
        "title": "Yoetz routine-read summary observation 1.0.0",
        "type": "object",
    }
    return cast(dict[str, JsonValue], document)


def _evidence_payload_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Derive additive evidence contracts from frozen v1.0 bytes."""

    source = (
        Path(__file__).resolve().parent.parent
        / "schemas/events/evidence-recorded-1.0.0.schema.json"
    )
    try:
        document = cast(dict[str, JsonValue], json.loads(source.read_bytes()))
        properties = cast(dict[str, JsonValue], document["properties"])
        all_of = cast(list[JsonValue], document["allOf"])
    except (KeyError, OSError, TypeError, json.JSONDecodeError) as exc:
        raise SchemaGenerationError(
            "evidence_schema_template_invalid", entries=(entry.relative_path,)
        ) from exc

    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    definitions = cast(dict[str, JsonValue], document.setdefault("$defs", {}))
    definitions.update(
        {
            "evidence_content_availability": {
                "enum": ["captured", "digest_only", "withheld"],
                "type": "string",
            },
            "evidence_digest_provenance": {
                "enum": [
                    "approved_check",
                    "caller_asserted",
                    "import_observed",
                    *(["observation_captured"] if entry.schema_version == "1.2.0" else []),
                ],
                "type": "string",
            },
            "evidence_digest_subject": {
                "enum": [
                    "approved_check_receipt",
                    "artifact_bytes",
                    "bounded_excerpt",
                    "command_stdout",
                    "import_report",
                    "source_diff",
                    "static_analysis_report",
                    "test_report",
                    "test_stdout",
                ],
                "type": "string",
            },
            "evidence_digest_binding": {
                "additionalProperties": False,
                "properties": {
                    "approval_commitment": {
                        "pattern": "^sha256:[0-9a-f]{64}$",
                        "type": "string",
                    },
                    "approved_check_result_digest": {
                        "pattern": "^sha256:[0-9a-f]{64}$",
                        "type": "string",
                    },
                    "byte_count": {
                        "maximum": 9_007_199_254_740_991,
                        "minimum": 0,
                        "type": "integer",
                    },
                    "content_availability": {"$ref": "#/$defs/evidence_content_availability"},
                    "provenance": {"$ref": "#/$defs/evidence_digest_provenance"},
                    "subject": {"$ref": "#/$defs/evidence_digest_subject"},
                },
                "required": ["subject", "content_availability", "byte_count", "provenance"],
                "type": "object",
            },
        }
    )
    properties["digest_binding"] = {"$ref": "#/$defs/evidence_digest_binding"}

    all_of.extend(
        [
            {
                "if": {"required": ["content_digest"]},
                "then": {"required": ["digest_binding"]},
            },
            {
                "if": {"required": ["digest_binding"]},
                "then": {"required": ["content_digest"]},
            },
            {
                "if": {
                    "properties": {
                        "digest_binding": {
                            "properties": {"content_availability": {"const": "captured"}},
                            "required": ["content_availability"],
                        }
                    },
                    "required": ["digest_binding"],
                },
                "then": {"required": ["captured_object_id"]},
            },
            {
                "if": {
                    "properties": {
                        "digest_binding": {
                            "properties": {
                                "content_availability": {"enum": ["digest_only", "withheld"]}
                            },
                            "required": ["content_availability"],
                        }
                    },
                    "required": ["digest_binding"],
                },
                "then": {"not": {"required": ["captured_object_id"]}},
            },
        ]
    )
    binding = cast(dict[str, JsonValue], definitions["evidence_digest_binding"])
    binding["allOf"] = [
        {
            "if": {
                "properties": {"provenance": {"const": "approved_check"}},
                "required": ["provenance"],
            },
            "then": {"required": ["approval_commitment", "approved_check_result_digest"]},
            "else": {
                "not": {
                    "anyOf": [
                        {"required": ["approval_commitment"]},
                        {"required": ["approved_check_result_digest"]},
                    ]
                }
            },
        },
        {
            "if": {
                "properties": {"subject": {"const": "approved_check_receipt"}},
                "required": ["subject"],
            },
            "then": {
                "properties": {"provenance": {"const": "approved_check"}},
                "required": ["provenance"],
            },
        },
        {
            "if": {
                "properties": {"subject": {"const": "import_report"}},
                "required": ["subject"],
            },
            "then": {
                "properties": {"provenance": {"const": "import_observed"}},
                "required": ["provenance"],
            },
        },
    ]
    compatible = {
        "artifact": ["artifact_bytes", "bounded_excerpt", "source_diff"],
        "command_output": [
            "approved_check_receipt",
            "command_stdout",
            "static_analysis_report",
            "test_report",
            "test_stdout",
        ],
        "test_result": [
            "approved_check_receipt",
            "static_analysis_report",
            "test_report",
            "test_stdout",
        ],
        "research_source": ["artifact_bytes", "bounded_excerpt"],
        "import_report": ["import_report"],
        "other": ["bounded_excerpt"],
    }
    for kind, subjects in compatible.items():
        all_of.append(
            {
                "if": {
                    "properties": {"evidence_kind": {"const": kind}},
                    "required": ["evidence_kind", "digest_binding"],
                },
                "then": {
                    "properties": {
                        "digest_binding": {
                            "properties": {"subject": {"enum": subjects}},
                            "required": ["subject"],
                        }
                    }
                },
            }
        )
    return document


def _claim_payload_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Derive v1.1 correction fields from the frozen v1.0 claim bytes."""

    source = (
        Path(__file__).resolve().parent.parent / "schemas/events/claim-recorded-1.0.0.schema.json"
    )
    try:
        document = cast(dict[str, JsonValue], json.loads(source.read_bytes()))
        properties = cast(dict[str, JsonValue], document["properties"])
        required = cast(list[JsonValue], document["required"])
    except (KeyError, OSError, TypeError, json.JSONDecodeError) as exc:
        raise SchemaGenerationError(
            "claim_schema_template_invalid", entries=(entry.relative_path,)
        ) from exc
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    properties["limitation_refs"] = {
        "items": {
            "pattern": "^res_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            "type": "string",
        },
        "maxItems": 64,
        "type": "array",
        "uniqueItems": True,
    }
    properties["supersedes_claim_refs"] = {
        "items": {
            "pattern": "^clm_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            "type": "string",
        },
        "maxItems": 16,
        "type": "array",
        "uniqueItems": True,
    }
    required.extend(("limitation_refs", "supersedes_claim_refs"))
    required.sort(key=lambda value: cast(str, value).encode("ascii"))
    return document


def _event_draft_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Derive v1.1 from the frozen v1.0 draft and add post-v1.0 claim and evidence pairs."""

    source = Path(__file__).resolve().parent.parent / "schemas/events/event-draft-1.0.0.schema.json"
    try:
        document = cast(dict[str, JsonValue], json.loads(source.read_bytes()))
        definitions = cast(dict[str, JsonValue], document["$defs"])
        branches = cast(list[JsonValue], document["oneOf"])
    except (KeyError, OSError, TypeError, json.JSONDecodeError) as exc:
        raise SchemaGenerationError(
            "event_draft_schema_template_invalid", entries=(entry.relative_path,)
        ) from exc

    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    document["title"] = "Yoetz event draft 1.1.0"
    opaque_branch = next(
        (
            item
            for item in branches
            if isinstance(item, dict)
            and item.get("$ref")
            == SCHEMA_NAMESPACE + "events/opaque-unknown-event-draft-1.0.0.schema.json"
        ),
        None,
    )
    if opaque_branch is None:
        raise SchemaGenerationError(
            "event_draft_schema_template_invalid", entries=(entry.relative_path,)
        )
    opaque_branch["$ref"] = SCHEMA_NAMESPACE + "events/opaque-unknown-event-draft-1.1.0.schema.json"
    branches[:] = [
        item
        for item in branches
        if not (
            isinstance(item, dict)
            and any(
                marker in json.dumps(item)
                for marker in (
                    "claim-recorded-1.1.0.schema.json",
                    "evidence-recorded-1.1.0.schema.json",
                    "evidence-recorded-1.2.0.schema.json",
                )
            )
        )
    ]
    evidence_legacy_index = next(
        (
            index
            for index, item in enumerate(branches)
            if isinstance(item, dict) and "evidence-recorded-1.0.0.schema.json" in json.dumps(item)
        ),
        None,
    )
    if evidence_legacy_index is None:
        raise SchemaGenerationError(
            "event_draft_schema_template_invalid", entries=(entry.relative_path,)
        )
    for offset, version in enumerate(("1.1.0", "1.2.0"), start=1):
        suffix = "_".join(version.split(".")[:2])
        definitions[f"schema_identity_evidence_recorded_{suffix}"] = {
            "additionalProperties": False,
            "properties": {
                "name": {"const": "evidence_recorded"},
                "version": {"const": version},
            },
            "required": ["name", "version"],
            "type": "object",
        }
        definitions[f"evidence_recorded_{suffix}_schema"] = {
            "$ref": f"#/$defs/schema_identity_evidence_recorded_{suffix}"
        }
        branches.insert(
            evidence_legacy_index + offset,
            {
                "properties": {
                    "payload": {
                        "$ref": (
                            "https://schemas.yoetz.dev/0.1/events/"
                            f"evidence-recorded-{version}.schema.json"
                        )
                    },
                    "schema": {"$ref": f"#/$defs/evidence_recorded_{suffix}_schema"},
                },
                "required": ["schema", "payload"],
            },
        )
    definitions["schema_identity_claim_recorded_1_1"] = {
        "additionalProperties": False,
        "properties": {
            "name": {"const": "claim_recorded"},
            "version": {"const": "1.1.0"},
        },
        "required": ["name", "version"],
        "type": "object",
    }
    definitions["claim_recorded_1_1_schema"] = {
        "$ref": "#/$defs/schema_identity_claim_recorded_1_1"
    }
    claim_branch: dict[str, JsonValue] = {
        "properties": {
            "payload": {
                "$ref": "https://schemas.yoetz.dev/0.1/events/claim-recorded-1.1.0.schema.json"
            },
            "schema": {"$ref": "#/$defs/claim_recorded_1_1_schema"},
        },
        "required": ["schema", "payload"],
    }
    claim_legacy_index = next(
        (
            index
            for index, item in enumerate(branches)
            if isinstance(item, dict) and "claim-recorded-1.0.0.schema.json" in json.dumps(item)
        ),
        None,
    )
    if claim_legacy_index is None:
        raise SchemaGenerationError(
            "event_draft_schema_template_invalid", entries=(entry.relative_path,)
        )
    branches.insert(claim_legacy_index + 1, claim_branch)
    return document


def _opaque_unknown_event_draft_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Exclude every exact-known pair, including additive claim and evidence versions."""

    source = (
        Path(__file__).resolve().parent.parent
        / "schemas/events/opaque-unknown-event-draft-1.0.0.schema.json"
    )
    try:
        document = cast(dict[str, JsonValue], json.loads(source.read_bytes()))
        definitions = cast(dict[str, JsonValue], document["$defs"])
        unknown = cast(dict[str, JsonValue], definitions["unknown_event_schema"])
        current_not = cast(dict[str, JsonValue], unknown["not"])
    except (KeyError, OSError, TypeError, json.JSONDecodeError) as exc:
        raise SchemaGenerationError(
            "opaque_unknown_event_schema_template_invalid", entries=(entry.relative_path,)
        ) from exc

    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    document["title"] = "Yoetz opaque unknown event draft 1.1.0"
    legacy = current_not
    if "anyOf" in current_not:
        values = cast(list[JsonValue], current_not["anyOf"])
        legacy = cast(dict[str, JsonValue], values[0])
    unknown["not"] = {
        "anyOf": [
            legacy,
            *(
                {
                    "additionalProperties": False,
                    "properties": {
                        "name": {"const": "evidence_recorded"},
                        "version": {"const": version},
                    },
                    "required": ["name", "version"],
                    "type": "object",
                }
                for version in ("1.1.0", "1.2.0")
            ),
            {
                "additionalProperties": False,
                "properties": {
                    "name": {"const": "claim_recorded"},
                    "version": {"const": "1.1.0"},
                },
                "required": ["name", "version"],
                "type": "object",
            },
        ]
    }
    return document


def _load_versioned_template(
    entry: _RegistryEntry,
    source_relative_path: str,
    *,
    replacements: Mapping[str, str] = {},
) -> dict[str, JsonValue]:
    """Copy one reviewed predecessor into a new append-only schema version."""

    source = Path(__file__).resolve().parent.parent / "schemas" / source_relative_path
    try:
        document = cast(dict[str, JsonValue], json.loads(source.read_bytes()))
    except (OSError, TypeError, json.JSONDecodeError) as exc:
        raise SchemaGenerationError(
            "versioned_schema_template_invalid", entries=(entry.relative_path,)
        ) from exc

    def rewrite(value: JsonValue) -> JsonValue:
        if isinstance(value, str):
            result = value
            for before, after in replacements.items():
                result = result.replace(before, after)
            return result
        if isinstance(value, list):
            return cast(JsonValue, [rewrite(item) for item in value])
        if isinstance(value, dict):
            return cast(JsonValue, {key: rewrite(item) for key, item in value.items()})
        return value

    copied = cast(dict[str, JsonValue], rewrite(document))
    copied["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    title = copied.get("title")
    if isinstance(title, str):
        copied["title"] = title.rsplit(" ", 1)[0] + f" {entry.schema_version}"
    return copied


def _runtime_attempt_evidence_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    digest = {
        "maxLength": 71,
        "minLength": 71,
        "pattern": "^sha256:[0-9a-f]{64}$",
        "type": "string",
    }
    correlation = {
        "maxLength": 256,
        "minLength": 1,
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]*$",
        "type": "string",
    }
    required = [
        "app_server_schema_sha256",
        "capability_cell_sha256",
        "capability_evidence_expires_at",
        "capability_profile",
        "case_disclosed",
        "credential_authority",
        "disclosed_case_sha256",
        "executable_sha256",
        "instruction_sha256",
        "isolated_config_sha256",
        "launcher_sha256",
        "output_schema_sha256",
        "process_cleanup",
        "reasoning_effort",
        "runtime_source_identity",
        "runtime_version",
        "selection_sha256",
        "turn_acknowledged",
        "upstream_body_observability",
    ]
    properties: dict[str, JsonValue] = {
        name: dict(digest)
        for name in (
            "app_server_schema_sha256",
            "capability_cell_sha256",
            "disclosed_case_sha256",
            "executable_sha256",
            "final_output_sha256",
            "instruction_sha256",
            "isolated_config_sha256",
            "launcher_sha256",
            "output_schema_sha256",
            "selection_sha256",
        )
    }
    properties.update(
        {
            "auth_mode": {"const": "chatgpt", "type": "string"},
            "capability_profile": {
                "maxLength": 256,
                "minLength": 1,
                "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$",
                "type": "string",
            },
            "capability_evidence_expires_at": {
                "maxLength": 20,
                "minLength": 20,
                "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
                "type": "string",
            },
            "case_disclosed": {"type": "boolean"},
            "credential_authority": {
                "const": "external_runtime_oauth",
                "type": "string",
            },
            "failure_stage": {
                "enum": sorted(
                    __import__(
                        "finishup.domain.findings", fromlist=["RUNTIME_FAILURE_STAGES"]
                    ).RUNTIME_FAILURE_STAGES
                    - ({"token_usage_invalid"} if entry.schema_version == "1.0.0" else set())
                ),
                "type": "string",
            },
            "plan_type": {
                "maxLength": 64,
                "minLength": 1,
                "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/-]*$",
                "type": "string",
            },
            "process_cleanup": {
                "enum": ["failed", "killed", "not_started", "terminated"],
                "type": "string",
            },
            "reasoning_effort": {
                "enum": ["high", "low", "max", "medium", "ultra", "xhigh"],
                "type": "string",
            },
            "runtime_source_identity": {
                "maxLength": 256,
                "minLength": 1,
                "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$",
                "type": "string",
            },
            "runtime_version": {
                "maxLength": 128,
                "minLength": 1,
                "pattern": "^[0-9A-Za-z][0-9A-Za-z._+-]*$",
                "type": "string",
            },
            "thread_id": dict(correlation),
            "turn_acknowledged": {"type": "boolean"},
            "turn_id": dict(correlation),
            "upstream_body_observability": {
                "const": "unavailable",
                "type": "string",
            },
        }
    )
    if entry.schema_version == "1.1.0":
        uint53_decimal = {
            "maxLength": 16,
            "pattern": (
                "^(?:0|[1-9][0-9]{0,14}|(?:[1-8][0-9]{15}|900[0-6][0-9]{12}|"
                "90070[0-9]{11}|90071[0-8][0-9]{10}|900719[0-8][0-9]{9}|"
                "9007199[01][0-9]{8}|90071992[0-4][0-9]{7}|900719925[0-3][0-9]{6}|"
                "9007199254[0-6][0-9]{5}|90071992547[0-3][0-9]{4}|"
                "9007199254740[0-8][0-9]{2}|90071992547409[0-8][0-9]|"
                "9007199254740990|9007199254740991))$"
            ),
            "type": "string",
        }
        properties["token_usage"] = {
            "additionalProperties": False,
            "properties": {
                name: dict(uint53_decimal)
                for name in (
                    "cached_input_tokens",
                    "cache_write_input_tokens",
                    "input_tokens",
                    "output_tokens",
                    "reasoning_output_tokens",
                    "total_tokens",
                )
            },
            "required": [
                "cached_input_tokens",
                "cache_write_input_tokens",
                "input_tokens",
                "output_tokens",
                "reasoning_output_tokens",
                "total_tokens",
            ],
            "type": "object",
        }
    return {
        "$id": SCHEMA_NAMESPACE + entry.relative_path,
        "$schema": _DRAFT_2020_12,
        "additionalProperties": False,
        "allOf": [
            {
                "if": {
                    "properties": {"turn_acknowledged": {"const": True}},
                    "required": ["turn_acknowledged"],
                },
                "then": {
                    "properties": {"case_disclosed": {"const": True}},
                    "required": ["thread_id", "turn_id"],
                },
            }
        ],
        "properties": properties,
        "required": required,
        "title": f"Yoetz runtime attempt evidence {entry.schema_version}",
        "type": "object",
    }


def _semantic_provenance_v1_1_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    document = _load_versioned_template(
        entry,
        "findings/semantic-provenance-1.0.0.schema.json",
    )
    definitions = cast(dict[str, JsonValue], document["$defs"])
    unavailable = cast(dict[str, JsonValue], definitions["status_unavailable"])
    unavailable_reason = cast(
        dict[str, JsonValue], cast(dict[str, JsonValue], unavailable["properties"])["reason"]
    )
    reasons = cast(list[JsonValue], unavailable_reason["enum"])
    if "outcome_unknown" not in reasons:
        reasons.append("outcome_unknown")
        reasons.sort(key=cast(Callable[[JsonValue], bytes], lambda item: str(item).encode()))
    semantic_reason = cast(dict[str, JsonValue], definitions["semantic_reason"])
    all_reasons = cast(list[JsonValue], semantic_reason["enum"])
    if "outcome_unknown" not in all_reasons:
        all_reasons.append("outcome_unknown")
        all_reasons.sort(key=cast(Callable[[JsonValue], bytes], lambda item: str(item).encode()))
    properties = cast(dict[str, JsonValue], document["properties"])
    dispatch = cast(dict[str, JsonValue], properties["dispatch_kind"])
    dispatch["enum"] = ["external", "external_runtime_oauth", "local_model"]
    properties["runtime_evidence"] = {
        "$ref": (f"{SCHEMA_NAMESPACE}findings/runtime-attempt-evidence-1.0.0.schema.json")
    }
    # Issue #582: present exactly when the declared fallback endpoint served this attempt. The
    # top-level provider/model/endpoint then name the fallback; this names the primary and the
    # closed reason it could not serve (a fallback-licensing class, or pre-dispatch
    # credential_unavailable). Optional and additive: single-endpoint provenance is unchanged.
    properties["fallback_from"] = {
        "additionalProperties": False,
        "properties": {
            # Decimal string like every other integer leaf on the wire (uint53_decimal shape).
            "attempted_count": {"maxLength": 1, "pattern": "^[0-8]$", "type": "string"},
            "endpoint_profile_id": {
                "maxLength": 128,
                "minLength": 1,
                "pattern": "^[a-z0-9][a-z0-9._-]*$",
                "type": "string",
            },
            "endpoint_profile_version": {
                "maxLength": 128,
                "minLength": 5,
                "type": "string",
            },
            "model": {
                "maxLength": 256,
                "minLength": 1,
                "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/-]*$",
                "type": "string",
            },
            "provider": {
                "maxLength": 128,
                "minLength": 1,
                "pattern": "^[a-z0-9][a-z0-9._-]*$",
                "type": "string",
            },
            "reason": {
                "enum": [
                    "credential_unavailable",
                    "provider_quota_exhausted",
                    "provider_rate_limited",
                    "provider_timeout",
                    "transport_unavailable",
                ],
                "type": "string",
            },
        },
        "required": [
            "attempted_count",
            "endpoint_profile_id",
            "endpoint_profile_version",
            "model",
            "provider",
            "reason",
        ],
        "type": "object",
    }
    rules = cast(list[JsonValue], document["allOf"])
    rules[0] = {
        "oneOf": [
            {
                "not": {
                    "anyOf": [
                        {"required": ["local_disclosure_reservation_id"]},
                        {"required": ["runtime_evidence"]},
                    ]
                },
                "properties": {"dispatch_kind": {"const": "external"}},
                "required": [
                    "dispatch_kind",
                    "egress_authorization_id",
                    "request_commitment",
                ],
            },
            {
                "not": {"required": ["local_disclosure_reservation_id"]},
                "properties": {"dispatch_kind": {"const": "external_runtime_oauth"}},
                "required": [
                    "dispatch_kind",
                    "egress_authorization_id",
                    "request_commitment",
                    "runtime_evidence",
                ],
            },
            {
                "not": {
                    "anyOf": [
                        {"required": ["egress_authorization_id"]},
                        {"required": ["request_commitment"]},
                        {"required": ["runtime_evidence"]},
                    ]
                },
                "properties": {"dispatch_kind": {"const": "local_model"}},
                "required": ["dispatch_kind", "local_disclosure_reservation_id"],
            },
        ]
    }
    return document


def _semantic_provenance_v1_2_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Carry the additive runtime-attempt evidence extension into current provenance."""

    document = _semantic_provenance_v1_1_schema(entry)
    properties = cast(dict[str, JsonValue], document["properties"])
    properties["runtime_evidence"] = {
        "$ref": (f"{SCHEMA_NAMESPACE}findings/runtime-attempt-evidence-1.1.0.schema.json")
    }
    return document


def _check_result_v1_1_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    document = _load_versioned_template(
        entry,
        "operations/check-result-1.0.0.schema.json",
        replacements={"semantic-provenance-1.0.0": "semantic-provenance-1.1.0"},
    )
    definitions = cast(dict[str, JsonValue], document["$defs"])
    binding = cast(dict[str, JsonValue], definitions["semantic_binding"])
    branches = cast(list[JsonValue], binding["oneOf"])
    template = next(
        cast(dict[str, JsonValue], item)
        for item in branches
        if isinstance(item, dict) and '"transport_unavailable"' in json.dumps(item)
    )
    unknown = cast(dict[str, JsonValue], json.loads(json.dumps(template)))
    props = cast(dict[str, JsonValue], unknown["properties"])
    cast(dict[str, JsonValue], props["semantic_reason"])["const"] = "outcome_unknown"
    provenance = cast(dict[str, JsonValue], props["semantic_provenance"])
    constraint = cast(dict[str, JsonValue], cast(list[JsonValue], provenance["allOf"])[1])
    constraint_props = cast(dict[str, JsonValue], constraint["properties"])
    cast(dict[str, JsonValue], constraint_props["reason"])["const"] = "outcome_unknown"
    branches.append(unknown)
    success = cast(dict[str, JsonValue], definitions["success"])
    success_props = cast(dict[str, JsonValue], success["properties"])
    reason_enum = cast(
        list[JsonValue], cast(dict[str, JsonValue], success_props["semantic_reason"])["enum"]
    )
    reason_enum.append("outcome_unknown")
    reason_enum.sort(key=cast(Callable[[JsonValue], bytes], lambda item: str(item).encode()))
    return document


def _check_recorded_v1_3_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    from finishup.domain.findings import MAX_RECORDED_VERDICTS, PRIOR_FINDING_VERDICTS
    from finishup.protocol.models import (
        MAX_MISSING_FOR_ASSESSMENT,
        MAX_MISSING_TARGET_REFS,
        MISSING_FOR_ASSESSMENT_KINDS,
        MISSING_ITEM_AVAILABILITIES,
    )

    document = _simple_versioned_schema(entry, "events/check-recorded-1.2.0.schema.json", {})
    properties = cast(dict[str, JsonValue], document["properties"])
    properties["semantic_conclusion"] = {
        "type": "string",
        "enum": ["no_material_discrepancy", "challenges_returned", "insufficient_packet"],
    }
    cast(list[JsonValue], document["required"]).append("semantic_conclusion")
    properties["semantic_status"] = {"const": "succeeded", "type": "string"}
    # Issue #905: the reviewer's admitted per-finding rulings, optional so every check written by
    # an earlier 0.3 build (and every check without rulings) keeps validating byte for byte.
    definitions = cast(dict[str, JsonValue], document["$defs"])
    definitions.setdefault(
        "opaque_ref",
        {
            "maxLength": 128,
            "minLength": 1,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]*$",
            "type": "string",
        },
    )
    definitions.setdefault(
        "digest",
        {"maxLength": 71, "minLength": 71, "pattern": "^sha256:[0-9a-f]{64}$", "type": "string"},
    )
    definitions.setdefault(
        "item_id_list_64",
        {
            "items": {"$ref": "#/$defs/opaque_ref"},
            "maxItems": 64,
            "minItems": 0,
            "type": "array",
            "uniqueItems": True,
        },
    )
    definitions["review_packet"] = {"properties": {}}
    _add_review_input_manifest_to_outbound_case({"$defs": definitions})
    definitions.pop("review_packet", None)
    properties["review_input_manifest"] = {"$ref": "#/$defs/review_input_manifest"}
    returned = cast(dict[str, JsonValue], properties["returned_finding_ids"])
    finding_ref = cast(dict[str, JsonValue], returned["items"])
    definitions["prior_finding_verdict"] = cast(
        JsonValue,
        {
            "additionalProperties": False,
            "properties": {
                "cited_refs": {
                    "items": {
                        "pattern": (
                            "^(act|clm|evd|evt|fnd|obl|res)_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}"
                            "-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
                        ),
                        "type": "string",
                    },
                    "maxItems": 16,
                    "type": "array",
                    "uniqueItems": True,
                },
                "finding_id": dict(finding_ref),
                "verdict": {
                    "enum": sorted(PRIOR_FINDING_VERDICTS, key=str.encode),
                    "type": "string",
                },
            },
            "required": ["cited_refs", "finding_id", "verdict"],
            "type": "object",
        },
    )
    properties["prior_finding_verdicts"] = {
        "items": {"$ref": "#/$defs/prior_finding_verdict"},
        "maxItems": MAX_RECORDED_VERDICTS,
        "minItems": 1,
        "type": "array",
    }
    # Issue #907: what an ``insufficient_packet`` review named as missing, classified by FinishUP
    # (kind, packet refs, availability; never reviewer prose). Optional for the same reason, and
    # admitted only beside an ``insufficient_packet`` conclusion.
    definitions["missing_item"] = cast(
        JsonValue,
        {
            "additionalProperties": False,
            "properties": {
                "availability": {
                    "enum": sorted(MISSING_ITEM_AVAILABILITIES, key=str.encode),
                    "type": "string",
                },
                "kind": {
                    "enum": sorted(MISSING_FOR_ASSESSMENT_KINDS, key=str.encode),
                    "type": "string",
                },
                "target_refs": {
                    "items": {
                        "pattern": (
                            "^(act|clm|evd|evt|fnd|obl|res)_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}"
                            "-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
                        ),
                        "type": "string",
                    },
                    "maxItems": MAX_MISSING_TARGET_REFS,
                    "type": "array",
                    "uniqueItems": True,
                },
            },
            "required": ["availability", "kind", "target_refs"],
            "type": "object",
        },
    )
    properties["missing_for_assessment"] = {
        "items": {"$ref": "#/$defs/missing_item"},
        "maxItems": MAX_MISSING_FOR_ASSESSMENT,
        "minItems": 1,
        "type": "array",
        "uniqueItems": True,
    }
    cast(list[JsonValue], document["allOf"]).append(
        {
            "anyOf": [
                {"not": {"required": ["missing_for_assessment"]}},
                {
                    "properties": {"semantic_conclusion": {"const": "insufficient_packet"}},
                    "required": ["semantic_conclusion"],
                },
            ]
        }
    )

    # ADR-031 (#883): keyed commitments to the check-time change files this review was shown.
    commitments: dict[str, JsonValue] = {
        "items": {"pattern": "^hmac-sha256:[0-9a-f]{64}$", "type": "string"},
        "maxItems": 128,
        "type": "array",
        "uniqueItems": True,
    }
    partial: dict[str, JsonValue] = {
        "items": {
            "additionalProperties": False,
            "properties": {
                "clean_bytes": {"maximum": 262144, "minimum": 0, "type": "integer"},
                "commitment": {"pattern": "^hmac-sha256:[0-9a-f]{64}$", "type": "string"},
                "redactions": {"maximum": 262144, "minimum": 0, "type": "integer"},
                "section_admitted": {"type": "boolean"},
                "shown_bytes": {"maximum": 262144, "minimum": 0, "type": "integer"},
                # R945-02: keyed commitment to where the view's redactions and hunks lie.
                # Optional only so a record written before it existed still decodes.
                "view_commitment": {"pattern": "^hmac-sha256:[0-9a-f]{64}$", "type": "string"},
            },
            "required": [
                "clean_bytes",
                "commitment",
                "redactions",
                "section_admitted",
                "shown_bytes",
            ],
            "type": "object",
        },
        "maxItems": 128,
        "type": "array",
        "uniqueItems": True,
    }
    properties["check_change_files"] = {
        "additionalProperties": False,
        "properties": {
            "complete": {"type": "boolean"},
            "fully_shown": commitments,
            "partially_shown": partial,
        },
        "required": ["complete", "fully_shown", "partially_shown"],
        "type": "object",
    }

    # Issue #904: the frontier references whose content item the reduced review packet sent. The
    # runtime also requires the reduced-scope coverage code beside it and ASCII-sorted order.
    properties["semantic_included_refs"] = {
        "items": {
            "pattern": (
                "^(act|clm|evd|evt|fnd|obl|res)_"
                "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
            ),
            "type": "string",
        },
        "maxItems": 576,
        "minItems": 1,
        "type": "array",
        "uniqueItems": True,
    }
    # Issue #920: bounded opaque item identities omitted by the heuristic never-send class.
    # The companion coverage gap is enforced by CheckRecordedPayload; the field itself remains
    # optional so older completed checks retain their exact event bytes.
    properties["semantic_withheld_item_ids"] = {
        "items": {
            "maxLength": 128,
            "minLength": 1,
            "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
            "type": "string",
        },
        "maxItems": 64,
        "type": "array",
        "uniqueItems": True,
    }
    return document


def _check_recorded_v1_1_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    document = _load_versioned_template(
        entry,
        "events/check-recorded-1.0.0.schema.json",
        replacements={"semantic-provenance-1.0.0": "semantic-provenance-1.1.0"},
    )
    definitions = cast(dict[str, JsonValue], document["$defs"])
    binding = cast(dict[str, JsonValue], definitions["semantic_binding"])
    branches = cast(list[JsonValue], binding["oneOf"])
    template = next(
        cast(dict[str, JsonValue], item)
        for item in branches
        if isinstance(item, dict) and '"transport_unavailable"' in json.dumps(item)
    )
    unknown = cast(dict[str, JsonValue], json.loads(json.dumps(template)))
    props = cast(dict[str, JsonValue], unknown["properties"])
    cast(dict[str, JsonValue], props["semantic_reason"])["const"] = "outcome_unknown"
    provenance = cast(dict[str, JsonValue], props["semantic_provenance"])
    constraint = cast(dict[str, JsonValue], cast(list[JsonValue], provenance["allOf"])[1])
    constraint_props = cast(dict[str, JsonValue], constraint["properties"])
    cast(dict[str, JsonValue], constraint_props["reason"])["const"] = "outcome_unknown"
    branches.append(unknown)
    properties = cast(dict[str, JsonValue], document["properties"])
    reason_enum = cast(
        list[JsonValue], cast(dict[str, JsonValue], properties["semantic_reason"])["enum"]
    )
    reason_enum.append("outcome_unknown")
    reason_enum.sort(key=cast(Callable[[JsonValue], bytes], lambda item: str(item).encode()))
    return document


def _simple_versioned_schema(
    entry: _RegistryEntry, source: str, replacements: Mapping[str, str]
) -> dict[str, JsonValue]:
    return _load_versioned_template(entry, source, replacements=replacements)


_RECEIPT_SCAN_STAGES: Final[tuple[str, ...]] = (
    "candidate",
    "legacy_unknown",
    "not_run",
    "prepared_case",
    "rendered_body",
)
_WITHHELD_ITEM_ID_SCHEMA: Final[dict[str, JsonValue]] = {
    "maxLength": 128,
    "minLength": 1,
    "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
    "type": "string",
}
_WITHHELD_ITEM_IDS_SCHEMA: Final[dict[str, JsonValue]] = {
    "items": _WITHHELD_ITEM_ID_SCHEMA,
    "maxItems": 64,
    "minItems": 1,
    "type": "array",
    "uniqueItems": True,
}
_WITHHELD_ITEM_REASON_SCHEMA: Final[dict[str, JsonValue]] = {
    "const": "never_send_heuristic",
    "type": "string",
}


def _extend_receipt_schema_fields(
    receipt: dict[str, JsonValue],
    *,
    reason_schema: dict[str, JsonValue],
    definitions: dict[str, JsonValue] | None = None,
) -> None:
    """Add the stage and heuristic-omission fields to an active receipt shape.

    The fields are optional for the active contract because old durable rows are read through the
    same projection.  Their dependencies remain closed: an omission identity always names the
    closed reason, and a ``not_run`` stage always names why no scan was performed.
    """

    properties = receipt.get("properties")
    local_definitions = receipt.get("$defs") if definitions is None else definitions
    if not isinstance(properties, dict) or not isinstance(local_definitions, dict):
        raise SchemaGenerationError("receipt_schema_template_invalid")
    scan = local_definitions.get("secret_scan")
    if scan is not None:
        if not isinstance(scan, dict) or not isinstance(scan.get("properties"), dict):
            raise SchemaGenerationError("receipt_secret_scan_schema_template_invalid")
        scan_properties = cast(dict[str, JsonValue], scan["properties"])
        scan_properties["stage"] = {"enum": list(_RECEIPT_SCAN_STAGES), "type": "string"}
        scan_properties["not_run_reason"] = reason_schema
        # Present only when the owner policy in force had the low-confidence credential heuristic
        # turned off for this disclosure (issue #982); absent means it was enforced.
        scan_properties["credential_heuristic"] = {"const": "disabled", "type": "string"}
        scan_all_of = scan.setdefault("allOf", [])
        if not isinstance(scan_all_of, list):
            raise SchemaGenerationError("receipt_secret_scan_schema_template_invalid")
        scan_all_of.extend(
            [
                {
                    "if": {"properties": {"stage": {"const": "not_run"}}, "required": ["stage"]},
                    "then": {"required": ["not_run_reason"]},
                },
                {
                    "if": {"required": ["not_run_reason"]},
                    "then": {
                        "required": ["stage"],
                        "properties": {"stage": {"const": "not_run"}},
                    },
                },
            ]
        )
    properties["withheld_item_ids"] = _WITHHELD_ITEM_IDS_SCHEMA
    properties["withheld_item_reason"] = _WITHHELD_ITEM_REASON_SCHEMA
    receipt_all_of = receipt.setdefault("allOf", [])
    if not isinstance(receipt_all_of, list):
        raise SchemaGenerationError("receipt_schema_template_invalid")
    receipt_all_of.extend(
        [
            {
                "if": {"required": ["withheld_item_ids"]},
                "then": {"required": ["withheld_item_reason"]},
            },
            {
                "if": {"required": ["withheld_item_reason"]},
                "then": {"required": ["withheld_item_ids"]},
            },
        ]
    )


def _egress_receipt_v1_1_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Derive the additive receipt contract while retaining old row compatibility."""

    document = _load_versioned_template(entry, "privacy/egress-receipt-1.0.0.schema.json")
    properties = cast(dict[str, JsonValue], document["properties"])
    properties["schema_version"] = {"enum": ["1.0.0", "1.1.0"], "type": "string"}
    definitions = cast(dict[str, JsonValue], document["$defs"])
    reason_schema = cast(dict[str, JsonValue], definitions["privacy_reason"])
    _extend_receipt_schema_fields(document, reason_schema=reason_schema)
    # The closed operation that asked for this network disclosure (tb4n2 N-5). Optional: rows
    # written before it, and a disclosure whose producer is not recognized, omit it.
    properties["origin_operation"] = {
        "enum": ["credential_probe", "observation_advice", "semantic_check"],
        "type": "string",
    }
    # #1118: one reviewer exchange on a route sized to its model's context carries up to 524,288
    # bytes (``MAX_SIZED_EXCHANGE_BYTES``, the outbound-document bound). 1.1.0 is unreleased, so
    # its bound widens in place; a 1.0.0 receipt keeps 262,144.
    definitions["max_524288_decimal"] = {
        "$ref": SCHEMA_NAMESPACE
        + "privacy/outbound-case-1.0.0.schema.json#/$defs/max_524288_decimal"
    }
    counts = cast(dict[str, JsonValue], definitions["counts"])
    count_properties = cast(dict[str, JsonValue], counts["properties"])
    count_properties["final_bytes"] = {"$ref": "#/$defs/max_524288_decimal"}
    # #1220: a receipt may also show the receipt-only ``declared_test_excerpt`` label, which no
    # privacy policy names. 1.1.0 is unreleased, so its category set widens in place.
    from finishup.domain.privacy import DataCategory

    definitions["receipt_category_set"] = {
        "items": {
            "enum": cast(list[JsonValue], sorted(str(category.value) for category in DataCategory)),
            "type": "string",
        },
        "maxItems": len(DataCategory),
        "minItems": 0,
        "type": "array",
        "uniqueItems": True,
    }
    for name in ("approved_categories", "blocked_categories"):
        properties[name] = {"$ref": "#/$defs/receipt_category_set"}
    document["title"] = "Yoetz egress receipt 1.1.0"
    return document


def _control_request_v2_6_1_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Carry the existing selected-observation contract over the local control boundary."""

    document = _simple_versioned_schema(entry, "service/control-request-2.6.0.schema.json", {})
    definitions = cast(dict[str, JsonValue], document["$defs"])
    envelope = cast(dict[str, JsonValue], definitions["observation_envelope"])
    envelope_properties = cast(dict[str, JsonValue], envelope["properties"])
    structural = cast(dict[str, JsonValue], envelope_properties["structural_payload"])
    properties = cast(dict[str, JsonValue], structural["properties"])
    source = (
        Path(__file__).resolve().parent.parent
        / "schemas/observations/routine-read-summary-1.0.0.schema.json"
    )
    summary = cast(dict[str, JsonValue], json.loads(source.read_bytes()))
    summary_envelope_properties = cast(dict[str, JsonValue], summary["properties"])
    summary_structural = cast(
        dict[str, JsonValue], summary_envelope_properties["structural_payload"]
    )
    summary_properties = cast(dict[str, JsonValue], summary_structural["properties"])
    route_fields = (
        "selection_task_id",
        "selection_session_id",
        "selection_writer_id",
        "selection_authority_generation",
    )
    for field in route_fields:
        properties[field] = summary_properties[field]
    structural["dependentRequired"] = {
        field: [peer for peer in route_fields if peer != field] for field in route_fields
    }
    properties["subject_state_digest"] = dict(
        cast(dict[str, JsonValue], properties["command_digest"])
    )
    properties["protection_reference"] = {
        "type": "string",
        "minLength": 40,
        "maxLength": 40,
        "pattern": "^(?:obl|clm|fnd)_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    }
    definitions["observation_envelope"] = {
        "oneOf": [
            envelope,
            {"$ref": SCHEMA_NAMESPACE + "observations/routine-read-summary-1.0.0.schema.json"},
        ]
    }
    return document


def _control_result_v2_6_1_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Repair local receipt purposes without changing released 2.6 bytes or egress rules."""

    document = _simple_versioned_schema(entry, "service/control-result-2.6.0.schema.json", {})
    definitions = cast(dict[str, JsonValue], document["$defs"])
    local_receipt = cast(dict[str, JsonValue], definitions["local_disclosure_receipt"])
    properties = cast(dict[str, JsonValue], local_receipt["properties"])
    # This is the domain's local-purpose grammar. The stored agent-projection purpose
    # contains underscores and cannot be renamed without changing canonical receipt bytes.
    definitions["local_disclosure_purpose"] = {
        "maxLength": 128,
        "minLength": 1,
        "pattern": "^[a-z][a-z0-9_-]{0,127}$",
        "type": "string",
    }
    properties["purpose"] = {"$ref": "#/$defs/local_disclosure_purpose"}
    return document


def _finding_v1_3_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Add the coordination finding and policy identity to the current finding reader."""

    document = _simple_versioned_schema(
        entry,
        "findings/finding-1.2.0.schema.json",
        {"semantic-provenance-1.1.0": "semantic-provenance-1.1.0"},
    )
    definitions = cast(dict[str, JsonValue], document["$defs"])
    finding_kind = cast(dict[str, JsonValue], definitions["finding_kind"])
    enum_values = cast(list[JsonValue], finding_kind["enum"])
    if "coordination_overlap" not in enum_values:
        enum_values.append("coordination_overlap")
        enum_values.sort(key=lambda item: str(item).encode("ascii"))
    priority = {
        "properties": {
            "kind": {"const": "coordination_overlap"},
            "priority": {"const": 2},
        },
        "required": ["kind", "priority"],
    }
    branches = cast(list[JsonValue], cast(list[JsonValue], document["allOf"])[1]["oneOf"])
    if priority not in branches:
        branches.append(priority)
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    document["title"] = f"Yoetz finding {entry.schema_version}"
    return document


def _provider_judgment_v1_1_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Freeze the exact constrained-output schema every provider cell sends (issue #905).

    The runtime request schema is the owning source: it renames the provider kind alias to the
    frozen ``FindingKindWire`` anchor and carries the curated reviewer glossary. Version 1.1.0
    adds the required per-finding ``prior_finding_verdicts`` array to every conclusion branch
    (issue #905) and the required ``missing_for_assessment`` list to ``insufficient_packet``
    (issue #907).
    """

    # The active provider builder is intentionally versioned forward.  Loading the reviewed
    # predecessor here keeps the released 1.1.0 bytes stable when the provider model gains a
    # required field in 1.2.0.
    document = _load_versioned_template(
        entry,
        "findings/provider-judgment-1.1.0.schema.json",
    )
    # Keep the reviewed predecessor byte-identical even if a local ripple previously stamped
    # its title with the version (the active 1.2 contract owns any title change).
    document["title"] = entry.schema_name
    return document


def _provider_judgment_v1_2_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Build the active provider contract with the required Part 2 review evidence."""

    from finishup.adapters.providers.openai_responses import build_judgment_json_schema

    document = cast(dict[str, JsonValue], dict(build_judgment_json_schema()))
    ordered: dict[str, JsonValue] = {
        "$id": SCHEMA_NAMESPACE + entry.relative_path,
        "$schema": _DRAFT_2020_12,
    }
    ordered.update(document)
    ordered["title"] = entry.schema_name
    return ordered


def _reviewer_reply_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """The reviewer loop reply (#1118): three read actions or the provider judgment."""

    from finishup.adapters.providers.reviewer_reply import reviewer_reply_schema

    ordered: dict[str, JsonValue] = {
        "$id": SCHEMA_NAMESPACE + entry.relative_path,
        "$schema": _DRAFT_2020_12,
    }
    ordered.update(reviewer_reply_schema(reads_allowed=True))
    ordered["title"] = entry.schema_name
    return ordered


def _add_semantic_finding_kinds(document: dict[str, JsonValue]) -> None:
    """Add the semantic review kinds to a new finding-family schema only."""

    definitions = cast(dict[str, JsonValue], document["$defs"])
    finding_kind = cast(dict[str, JsonValue], definitions["finding_kind"])
    enum_values = cast(list[JsonValue], finding_kind["enum"])
    # Issue #1043 adds ``agent_criterion_unmet`` (priority 2) on the same unreleased versions.
    semantic_kinds = (
        ("code_defect", 1),
        ("task_requirement_unmet", 1),
        ("agent_criterion_unmet", 2),
        ("decision_needed", 3),
    )
    for value, _priority in semantic_kinds:
        if value not in enum_values:
            enum_values.append(value)
    enum_values.sort(key=lambda item: str(item).encode("ascii"))
    all_of = cast(list[JsonValue], document["allOf"])
    branches = cast(list[JsonValue], all_of[1]["oneOf"])
    for value, priority in semantic_kinds:
        branch: JsonValue = {
            "properties": {"kind": {"const": value}, "priority": {"const": priority}},
            "required": ["kind", "priority"],
        }
        if branch not in branches:
            branches.append(branch)


def _finding_v1_4_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Add the semantic reviewer finding kinds without mutating the frozen 1.3.0 schema."""

    document = _load_versioned_template(entry, "findings/finding-1.3.0.schema.json")
    _add_semantic_finding_kinds(document)
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    document["title"] = f"Yoetz finding {entry.schema_version}"
    return document


def _finding_recorded_v1_3_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """The finding event payload: the public finding plus the optional review-dialogue fields.

    The public ``finding`` object stays closed at 1.3.0. The (unreleased) 1.3.0 event payload is
    that object plus the optional closed ``challenge`` record and the ``relates_to`` link (issue
    #905); only an AI-powered finding may carry them, and a finding without them keeps its earlier
    bytes, so every row written by an earlier 0.3 build still validates.
    """

    from finishup.domain.findings import MAX_RELATED_FINDING_IDS, REVIEWER_NEXT_STEPS
    from finishup.protocol.models import MAX_REVIEW_TEXT_BYTES

    document = _load_versioned_template(entry, "findings/finding-1.3.0.schema.json")
    definitions = cast(dict[str, JsonValue], document["$defs"])
    properties = cast(dict[str, JsonValue], document["properties"])
    # Code points never exceed UTF-8 bytes, so this admits every byte-bounded domain value.
    review_text: dict[str, JsonValue] = {
        "maxLength": MAX_REVIEW_TEXT_BYTES,
        "minLength": 1,
        "type": "string",
    }
    definitions["review_text"] = review_text
    definitions["finding_challenge"] = cast(
        JsonValue,
        {
            "additionalProperties": False,
            "properties": {
                "alternative_interpretation": {"$ref": "#/$defs/review_text"},
                "discrepancy": {"$ref": "#/$defs/review_text"},
                "requested_next_step": {
                    "enum": sorted(REVIEWER_NEXT_STEPS, key=str.encode),
                    "type": "string",
                },
                "uncertainty": {"$ref": "#/$defs/review_text"},
            },
            "required": [
                "discrepancy",
                "alternative_interpretation",
                "requested_next_step",
                "uncertainty",
            ],
            "type": "object",
        },
    )
    properties["challenge"] = {"$ref": "#/$defs/finding_challenge"}
    properties["relates_to"] = {
        "items": {"$ref": "#/$defs/finding_id"},
        "maxItems": MAX_RELATED_FINDING_IDS,
        "minItems": 1,
        "type": "array",
        "uniqueItems": True,
    }
    all_of = cast(list[JsonValue], document["allOf"])
    all_of.append(
        {
            "if": {
                "anyOf": [{"required": ["challenge"]}, {"required": ["relates_to"]}],
            },
            "then": {
                "properties": {"origin": {"const": "semantic_model_derived"}},
                "required": ["origin"],
            },
        }
    )
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    document["title"] = f"Yoetz finding recorded {entry.schema_version}"
    return document


def _finding_recorded_v1_4_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Add challenge snippets and semantic finding kinds to the new finding event version."""

    document = _finding_recorded_v1_3_schema(entry)
    definitions = cast(dict[str, JsonValue], document["$defs"])
    challenge = cast(dict[str, JsonValue], definitions["finding_challenge"])
    challenge_properties = cast(dict[str, JsonValue], challenge["properties"])
    challenge_properties["snippet"] = {"$ref": "#/$defs/review_text"}
    _add_semantic_finding_kinds(document)
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    document["title"] = f"Yoetz finding recorded {entry.schema_version}"
    return document


def _policy_lineage(policy_id: str) -> list[JsonValue]:
    from finishup.protocol.policy_packs import CURRENT_POLICY_VERSIONS, LEGACY_POLICY_VERSIONS

    return [*LEGACY_POLICY_VERSIONS[policy_id], CURRENT_POLICY_VERSIONS[policy_id]]


def _admit_recorded_policy_identities(document: dict[str, JsonValue]) -> None:
    """Admit every recorded version of each built-in pack the active contract names.

    The unreleased 0.3 contracts first pinned every pack at ``0.1.0``. New checks run only the
    current versions (``finishup.protocol.policy_packs``), but a recorded check or finding, a check
    result replayed from the ledger, and a result an earlier 0.3 service shaped keep the identity
    they were written with, so the active result and event contracts admit both. A pack named by
    a constant ``policy_id`` admits only its own lineage; a shared definition admits the union.
    """

    from finishup.protocol.policy_packs import RECORDED_POLICY_PACKS, RECORDED_POLICY_VERSION_VALUES

    def admit(node: JsonValue) -> None:
        if isinstance(node, list):
            for item in node:
                admit(item)
            return
        if not isinstance(node, dict):
            return
        properties = node.get("properties")
        if isinstance(properties, dict):
            version = properties.get("policy_version")
            if isinstance(version, dict) and version.get("const") == "0.1.0":
                policy = properties.get("policy_id")
                values: list[JsonValue] = (
                    _policy_lineage(cast(str, policy["const"]))
                    if isinstance(policy, dict) and type(policy.get("const")) is str
                    else list(RECORDED_POLICY_VERSION_VALUES)
                )
                version.pop("const")
                if len(values) == 1:
                    version["const"] = values[0]
                else:
                    version["enum"] = values
            packs = properties.get("policy_packs")
            if isinstance(packs, dict) and isinstance(items := packs.get("items"), dict):
                listed = items.get("enum")
                if isinstance(listed, list):
                    policy_ids = {str(value).split("/", 1)[0] for value in listed}
                    items["enum"] = [
                        pack
                        for pack in RECORDED_POLICY_PACKS
                        if pack.split("/", 1)[0] in policy_ids
                    ]
        for value in node.values():
            admit(value)

    admit(document)


def _select_current_policy_packs(document: dict[str, JsonValue]) -> None:
    """A check request selects only the pack versions new checks run."""

    from finishup.protocol.policy_packs import CURRENT_POLICY_PACKS

    properties = cast(dict[str, JsonValue], document["properties"])
    policy_packs = cast(dict[str, JsonValue], properties["policy_packs"])
    items = cast(dict[str, JsonValue], policy_packs["items"])
    items["enum"] = list(CURRENT_POLICY_PACKS)
    policy_packs["maxItems"] = len(CURRENT_POLICY_PACKS)


def _check_totals_schema() -> dict[str, JsonValue]:
    """Closed structural counters; prose and caller-defined keys are never admitted."""

    from finishup.domain.check_totals import CHECK_TOTAL_FLAG_KEYS, CHECK_TOTAL_KEYS

    groups: dict[str, JsonValue] = {}
    for group, keys in sorted(CHECK_TOTAL_KEYS.items()):
        ordered = sorted(keys)
        groups[group] = {
            "additionalProperties": False,
            "properties": {
                key: (
                    {"enum": ["0", "1"], "type": "string"}
                    if (group, key) in CHECK_TOTAL_FLAG_KEYS
                    else {
                        "maxLength": 20,
                        "pattern": "^(0|[1-9][0-9]{0,19})$",
                        "type": "string",
                    }
                )
                for key in ordered
            },
            "required": ordered,
            "type": "object",
        }
    return {
        "additionalProperties": False,
        "properties": groups,
        "required": sorted(groups),
        "type": "object",
    }


def _check_recorded_v1_4_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Add the persisted Part 2 reviewer fields to the new check event version."""

    from finishup.protocol.models import MAX_REVIEW_TEXT_BYTES

    document = _check_recorded_v1_3_schema(entry)
    definitions = cast(dict[str, JsonValue], document["$defs"])
    properties = cast(dict[str, JsonValue], document["properties"])
    definitions["review_text"] = {
        "maxLength": MAX_REVIEW_TEXT_BYTES,
        "minLength": 1,
        "type": "string",
    }
    definitions["verified_item"] = {
        "additionalProperties": False,
        "allOf": [
            {
                "if": {
                    "properties": {"verdict": {"const": "not_assessable"}},
                    "required": ["verdict"],
                },
                "then": {"not": {"required": ["snippet"]}},
            },
            {
                "if": {
                    "properties": {"verdict": {"enum": ["not_supported", "supported"]}},
                    "required": ["verdict"],
                },
                "then": {"required": ["snippet"]},
            },
        ],
        "properties": {
            "cited_refs": {
                "items": {"$ref": "#/$defs/subject_id"},
                "maxItems": 16,
                "minItems": 1,
                "type": "array",
                "uniqueItems": True,
            },
            "requirement_or_claim": {"$ref": "#/$defs/review_text"},
            "snippet": {"$ref": "#/$defs/review_text"},
            "verdict": {
                "enum": ["not_assessable", "not_supported", "supported"],
                "type": "string",
            },
        },
        "required": ["cited_refs", "requirement_or_claim", "verdict"],
        "type": "object",
    }
    definitions["subject_id"] = {
        "pattern": (
            r"^(act|clm|evd|evt|fnd|obl|res)_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
            r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        ),
        "type": "string",
    }
    properties["review_summary"] = {"$ref": "#/$defs/review_text"}
    definitions["check_totals"] = _check_totals_schema()
    properties["totals"] = {"$ref": "#/$defs/check_totals"}
    properties["verified"] = {
        "items": {"$ref": "#/$defs/verified_item"},
        "maxItems": 64,
        "type": "array",
        "uniqueItems": True,
    }
    _add_semantic_redacted_values(definitions, properties)
    _add_semantic_route_required(properties)
    _add_check_review_mode(definitions, properties)
    _add_deliverable_states(definitions, properties)
    _admit_recorded_policy_identities(document)
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    document["title"] = f"Yoetz check recorded {entry.schema_version}"
    return document


_DEFERRED_BEFORE_FIRST_EDIT_REASON: Final = "deferred_before_first_edit"


def _admit_deferred_before_first_edit(document: dict[str, JsonValue]) -> None:
    """Admit ``not_requested`` / ``deferred_before_first_edit`` on check 1.5.0 only.

    1.4.0 and earlier stay byte-identical. The new branch is a copy of the local-only
    ``not_requested`` branch, and the reason enum gains the token in ASCII order.
    """

    definitions = cast(dict[str, JsonValue], document["$defs"])
    binding = cast(dict[str, JsonValue], definitions["semantic_binding"])
    branches = cast(list[JsonValue], binding["oneOf"])
    template = next(
        cast(dict[str, JsonValue], item)
        for item in branches
        if isinstance(item, dict)
        and cast(
            dict[str, JsonValue],
            cast(dict[str, JsonValue], item["properties"])["semantic_reason"],
        ).get("const")
        == "deterministic_mode"
        and cast(
            dict[str, JsonValue],
            cast(dict[str, JsonValue], item["properties"])["semantic_status"],
        ).get("const")
        == "not_requested"
    )
    clone = cast(dict[str, JsonValue], json.loads(json.dumps(template)))
    clone_props = cast(dict[str, JsonValue], clone["properties"])
    cast(dict[str, JsonValue], clone_props["semantic_reason"])["const"] = (
        _DEFERRED_BEFORE_FIRST_EDIT_REASON
    )
    branches.insert(branches.index(template) + 1, clone)
    if "success" in definitions:
        holder = cast(
            dict[str, JsonValue],
            cast(dict[str, JsonValue], definitions["success"])["properties"],
        )
    else:
        holder = cast(dict[str, JsonValue], document["properties"])
    reason_enum = cast(
        list[JsonValue], cast(dict[str, JsonValue], holder["semantic_reason"])["enum"]
    )
    if _DEFERRED_BEFORE_FIRST_EDIT_REASON not in reason_enum:
        encoded = _DEFERRED_BEFORE_FIRST_EDIT_REASON.encode()
        at = next(
            (index for index, item in enumerate(reason_enum) if str(item).encode() > encoded),
            len(reason_enum),
        )
        reason_enum.insert(at, _DEFERRED_BEFORE_FIRST_EDIT_REASON)


def _check_recorded_v1_5_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Admit the pre-edit deferral reason on check-recorded 1.5.0 (n6 item 4)."""

    document = _check_recorded_v1_4_schema(entry)
    _admit_deferred_before_first_edit(document)
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    # New document (ADR-048): prose title uses FinishUP; the yoetz.dev $id stays frozen.
    document["title"] = f"FinishUP check recorded {entry.schema_version}"
    return document


def _correctness_advisories_schema(*, history: bool = False) -> dict[str, JsonValue]:
    """#1162: routine correctness notes; subjects are the fence-resolved refs of the challenge.

    The fence resolves an ``act_``/``res_``/``evd_`` citation to its source event and a cited
    finding to its subjects, so a note carries at most the subjects a finding may name (64).
    """

    from finishup.domain.correctness_advisories import (
        ADVISORY_ID_PATTERN,
        MAX_ADVISORY_SUBJECT_REFS,
    )

    properties: dict[str, JsonValue] = {
        "summary": {"type": "string", "minLength": 1, "maxLength": 8192},
        "detail": {"type": "string", "minLength": 1, "maxLength": 8192},
        "subject_refs": {
            "type": "array",
            "maxItems": MAX_ADVISORY_SUBJECT_REFS,
            "uniqueItems": True,
            "items": {
                "type": "string",
                "pattern": r"^(?:evt|obl|clm)_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            },
        },
    }
    required: list[JsonValue] = ["summary", "detail", "subject_refs"]
    if not history:
        # #1162 tracked advice (in place on the unreleased 1.6.0): where the row came from. A row
        # without it is a routine correctness note, so the first shape stays valid unchanged.
        from finishup.domain.correctness_advisories import ADVISORY_ORIGINS

        properties["origin"] = {
            "type": "string",
            "enum": cast(list[JsonValue], sorted(ADVISORY_ORIGINS, key=str.encode)),
        }
        # #1145 (in place): the pinned digest of the declared test a ``declared_test_verdict`` row
        # is about, present on exactly those rows (the decoder enforces the pairing).
        properties["test_digest"] = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
    if history:
        for key in ("summary", "detail"):
            properties[key] = {"anyOf": [properties[key], {"$ref": "#/$defs/finding_omission"}]}
        properties.update(
            {
                "advisory_id": {"type": "string", "pattern": ADVISORY_ID_PATTERN},
                "disposition": {
                    "enum": [
                        "addressed",
                        "declined",
                        "no_recorded_response",
                    ],
                    "type": "string",
                },
                "reason": {
                    "anyOf": [
                        {"type": "string", "minLength": 1, "maxLength": 4096},
                        {"$ref": "#/$defs/finding_omission"},
                    ]
                },
                "response_event_id": {"$ref": "#/$defs/event_id"},
                "evidence_refs": {
                    "type": "array",
                    "maxItems": 64,
                    "uniqueItems": True,
                    "items": {
                        "type": "string",
                        "pattern": r"^(?:evd|res)_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
                    },
                },
            }
        )
        required += ["advisory_id", "disposition"]
    return {
        "type": "array",
        "maxItems": 10,
        "minItems": 1,
        "items": {
            "type": "object",
            "additionalProperties": False,
            "properties": properties,
            "required": required,
        },
    }


def _outcome_correctness_advisories_schema() -> dict[str, JsonValue]:
    """The check result's advisory rows without the reviewer's summary (status operation view)."""

    document = _check_correctness_advisories_schema()
    items = cast(dict[str, JsonValue], document["items"])
    cast(dict[str, JsonValue], items["properties"]).pop("summary")
    items["required"] = ["advisory_id", "origin", "subject_refs"]
    return document


def _check_correctness_advisories_schema() -> dict[str, JsonValue]:
    """#1162 tracked advice: a check's advisory rows with identities (check-result 1.6.0, in place).

    Identity, closed origin and subjects are structural; the summary is the reviewer's
    privacy-projected words. A routine note's row has no stored origin and reads as
    ``routine_correctness_note`` here.
    """

    from finishup.domain.correctness_advisories import (
        ADVISORY_ID_PATTERN,
        MAX_ADVISORIES_PER_CHECK,
        MAX_ADVISORY_SUBJECT_REFS,
    )

    return {
        "type": "array",
        "maxItems": MAX_ADVISORIES_PER_CHECK,
        "items": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "advisory_id": {"type": "string", "pattern": ADVISORY_ID_PATTERN},
                "origin": {
                    "type": "string",
                    "enum": [
                        "declared_test_verdict",
                        "routine_correctness_note",
                        "strongest_remaining_check",
                        "verified_not_assessable",
                        "verified_not_supported",
                    ],
                },
                "subject_refs": {
                    "type": "array",
                    "maxItems": MAX_ADVISORY_SUBJECT_REFS,
                    "uniqueItems": True,
                    "items": {
                        "type": "string",
                        "pattern": r"^(?:evt|obl|clm)_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
                    },
                },
                "summary": {
                    "oneOf": [
                        {"type": "string", "minLength": 1, "maxLength": 8192},
                        {"$ref": "#/$defs/finding_omission"},
                    ]
                },
            },
            "required": ["advisory_id", "origin", "subject_refs", "summary"],
        },
    }


def _advisory_counts_schema() -> dict[str, JsonValue]:
    fields = ("total", "no_recorded_response", "withheld_may_answer")
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            key: {"type": "string", "pattern": r"^(?:0|[1-9][0-9]{0,18})$", "maxLength": 19}
            for key in fields
        },
        "required": cast(list[JsonValue], list(fields)),
    }


def _advisory_response_schema() -> dict[str, JsonValue]:
    from finishup.domain.correctness_advisories import ADVISORY_ID_PATTERN

    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "advisory_id": {"type": "string", "pattern": ADVISORY_ID_PATTERN},
            "disposition": {"type": "string", "enum": ["addressed", "declined"]},
            "evidence_refs": {
                "type": "array",
                "maxItems": 64,
                "uniqueItems": True,
                "items": {
                    "type": "string",
                    "pattern": r"^(?:evd|res)_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
                },
            },
        },
        "required": ["advisory_id", "disposition", "evidence_refs"],
        "allOf": [
            {
                "if": {"properties": {"disposition": {"const": "addressed"}}},
                "then": {"properties": {"evidence_refs": {"minItems": 1}}},
            }
        ],
    }


def _admit_advisory_dispositions(
    properties: dict[str, JsonValue], rules: list[JsonValue], *, evidence_field: str
) -> None:
    from finishup.domain.correctness_advisories import ADVISORY_ID_PATTERN

    dispositions = cast(
        list[JsonValue], cast(dict[str, JsonValue], properties["disposition"])["enum"]
    )
    dispositions.extend(["addressed", "declined"])
    dispositions.sort(key=lambda value: str(value).encode("ascii"))
    properties["finding_id"] = {
        "anyOf": [properties["finding_id"], {"type": "string", "pattern": ADVISORY_ID_PATTERN}]
    }
    rules.append(
        {
            "if": {"properties": {"disposition": {"enum": ["addressed", "declined"]}}},
            "then": {
                **_no_waiver_fields(),
                "required": ["reason"],
                "properties": {"finding_id": {"pattern": ADVISORY_ID_PATTERN}},
                "not": {
                    "anyOf": [
                        {"required": ["waiver_scope"]},
                        {"required": ["waiver_expiry"]},
                        {"required": ["duplicate_of_finding_id"]},
                    ]
                },
            },
            "else": {"properties": {"finding_id": {"$ref": "#/$defs/finding_id"}}},
        }
    )
    rules.append(
        {
            "if": {"properties": {"disposition": {"const": "addressed"}}},
            "then": {"required": [evidence_field], "properties": {evidence_field: {"minItems": 1}}},
        }
    )


def _check_recorded_v1_6_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """#1118: check-recorded 1.6.0 is 1.5.0 plus the optional reviewer conversation record.

    A new version relative to the released line: a 1.4.0/1.5.0 reader keeps rejecting the field,
    and an older build preserves a 1.6.0 event it does not know as an opaque unknown version.
    #1162 adds the optional ``correctness_advisories`` in place. That follows the repository rule
    for wire versions: an unreleased version on an integration line may be amended in place until
    it ships in a release; a released version is never amended. 1.6.0 is on no release tag and on
    neither ``main`` nor ``0.3``, so only builds of this unreleased line ever read it.
    """

    document = _check_recorded_v1_5_schema(entry)
    _admit_stopped_review(document)
    _add_test_check_to_review_input_manifest(document)
    definitions = cast(dict[str, JsonValue], document["$defs"])
    _add_reviewer_definitions(definitions)
    cast(dict[str, JsonValue], document["properties"])["correctness_advisories"] = (
        _correctness_advisories_schema()
    )
    cast(dict[str, JsonValue], document["properties"])["reviewer"] = {
        "$ref": "#/$defs/reviewer_record"
    }
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    document["title"] = f"FinishUP check recorded {entry.schema_version}"
    return document


def _check_request_v1_1_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Select the current built-in packs, including the dedicated coordination policy."""

    document = _load_versioned_template(entry, "operations/check-request-1.0.0.schema.json")
    _select_current_policy_packs(document)
    # Issue #976, unreleased in-place addition: request the closing review (final phase) with or
    # without a completion claim. Absent requests keep their exact shape.
    properties = cast(dict[str, JsonValue], document["properties"])
    properties["final_review"] = {"type": "boolean"}
    # Issue #1012, unreleased in-place addition: wait, bounded, for the caller's pending hook
    # observations before the case freezes. Absent requests keep their exact shape.
    properties["await_observations"] = {"type": "boolean"}
    # Issue #1048 (ADR-047), unreleased in-place addition: ``inspect`` reads what is left to
    # close instead of checking. It records nothing and mints no findings, so the request model
    # refuses the finding, pack, closing-review and scope options beside it. That rule stays out
    # of this document on purpose: a root conditional lowers the whole advertised check input to
    # ``unknown`` on the observed hosts (the presentation budget admits none on ``check``).
    mode = cast(dict[str, JsonValue], properties["mode"])
    modes: set[str] = {str(value) for value in cast(list[JsonValue], mode["enum"])}
    mode["enum"] = cast(
        JsonValue, sorted(modes | {"inspect"}, key=lambda value: value.encode("ascii"))
    )
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    document["title"] = f"Yoetz check request {entry.schema_version}"
    return document


_LINEAGE_ID_PATTERNS: Final[Mapping[str, str]] = {
    "task_id": r"^tsk_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    "event_id": r"^evt_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    "receipt_id": r"^rcp_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    "finding_id": r"^fnd_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    "project_id": r"^prj_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
}
_LINEAGE_UINT_PATTERN: Final = r"^(?:0|[1-9][0-9]{0,17}|[1-8][0-9]{18}|9[0-1][0-9]{17}|92[0-1][0-9]{16}|922[0-2][0-9]{15}|9223[0-2][0-9]{14}|92233[0-6][0-9]{13}|922337[0-1][0-9]{12}|92233720[0-2][0-9]{10}|922337203[0-5][0-9]{9}|9223372036[0-7][0-9]{8}|92233720368[0-4][0-9]{7}|922337203685[0-3][0-9]{6}|9223372036854[0-6][0-9]{5}|92233720368547[0-6][0-9]{4}|922337203685477[0-4][0-9]{3}|9223372036854775[0-7][0-9]{2}|922337203685477580[0-6]|9223372036854775807)$"
_LINEAGE_POSITIVE_UINT_PATTERN: Final = _LINEAGE_UINT_PATTERN.replace(r"(?:0|", r"(?:")


def _lineage_id_schema(kind: str) -> dict[str, JsonValue]:
    return {"pattern": _LINEAGE_ID_PATTERNS[kind], "type": "string"}


def _lineage_frontier_schema() -> dict[str, JsonValue]:
    return {"$ref": SCHEMA_NAMESPACE + "common/frontier-1.0.0.schema.json"}


def _lineage_enum_schema(values: Sequence[str]) -> dict[str, JsonValue]:
    return {"enum": list(values), "type": "string"}


def _lineage_vocabulary_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Build one shared closed lineage vocabulary schema."""

    values: Mapping[str, tuple[str, ...]] = {
        "work-state": ("open", "closed", "cancelled", "abandoned", "written_off"),
        "session-health": ("active", "contact_lost", "ended"),
        "lineage-origin": ("parent_minted", "self_registered", "host_observed"),
        "lineage-acceptance": ("pending", "accepted", "rejected"),
    }
    try:
        enum_values = values[entry.schema_name]
    except KeyError as exc:
        raise SchemaGenerationError(
            "lineage_vocabulary_unknown", entries=(entry.relative_path,)
        ) from exc
    return _normalize({"enum": list(enum_values), "type": "string"}, entry)


def _lineage_child_finding_schema() -> dict[str, JsonValue]:
    traits = {
        "completion_with_open_obligations": (1, True),
        "requested_item_never_attempted": (2, True),
        "failed_work_omitted": (1, True),
        "claim_without_admissible_evidence": (1, True),
        "result_without_action": (2, True),
        "action_without_result": (3, True),
        "stale_evidence_for_changed_state": (2, True),
        "contradictory_claims_unresolved": (1, True),
        "ledger_stale_or_incomplete": (3, False),
        "weak_or_stale_response": (2, True),
        "evidence_does_not_support_claim": (1, True),
        "diff_does_not_match_account": (1, True),
        "material_limitation_omitted": (1, True),
        "questionable_finding_rejection": (2, True),
        "coordination_overlap": (2, True),
        "code_defect": (1, True),
        "task_requirement_unmet": (1, True),
        "agent_criterion_unmet": (2, True),
        "decision_needed": (3, False),
    }
    return {
        "additionalProperties": False,
        "allOf": [
            *(
                {
                    "if": {
                        "properties": {"kind": {"const": kind}},
                        "required": ["kind"],
                    },
                    "then": {
                        "properties": {
                            "actionable": {"const": actionable},
                            "priority": {"const": priority},
                        }
                    },
                }
                for kind, (priority, actionable) in traits.items()
            ),
            {
                "if": {"properties": {"resolved": {"const": True}}, "required": ["resolved"]},
                "then": {
                    "properties": {"resolution_event_id": _lineage_id_schema("event_id")},
                    "required": ["resolution_event_id"],
                },
            },
            {
                "if": {"required": ["resolution_event_id"]},
                "then": {"properties": {"resolved": {"const": True}}},
            },
            # Issue #984: a child repair only the child agent verified stays unresolved and
            # actionable by kind; the field is present only when true.
            {
                "if": {"required": ["self_verified"]},
                "then": {
                    "properties": {
                        "actionable": {"const": True},
                        "resolved": {"const": False},
                    }
                },
            },
        ],
        "properties": {
            "actionable": {"type": "boolean"},
            "finding_id": _lineage_id_schema("finding_id"),
            "kind": _lineage_enum_schema(
                [
                    "action_without_result",
                    "claim_without_admissible_evidence",
                    "coordination_overlap",
                    "completion_with_open_obligations",
                    "contradictory_claims_unresolved",
                    "diff_does_not_match_account",
                    "evidence_does_not_support_claim",
                    "failed_work_omitted",
                    "ledger_stale_or_incomplete",
                    "material_limitation_omitted",
                    "questionable_finding_rejection",
                    "requested_item_never_attempted",
                    "result_without_action",
                    "stale_evidence_for_changed_state",
                    "weak_or_stale_response",
                    # The AI-powered review kinds (finding 1.4.0), carried under their own names
                    # so a delegated child's finding validates in the parent's manifest and
                    # receipt (issue #1043 review; unreleased on 0.3, widened in place).
                    "code_defect",
                    "task_requirement_unmet",
                    "agent_criterion_unmet",
                    "decision_needed",
                ]
            ),
            "origin": _lineage_enum_schema(["deterministic", "semantic_model_derived"]),
            "priority": {"maximum": 3, "minimum": 1, "type": "integer"},
            "resolution_event_id": {"oneOf": [_lineage_id_schema("event_id"), {"type": "null"}]},
            "resolved": {"type": "boolean"},
            "self_verified": {"const": True},
        },
        "required": [
            "actionable",
            "finding_id",
            "kind",
            "origin",
            "priority",
            "resolved",
        ],
        "type": "object",
    }


def _lineage_child_snapshot_schema() -> dict[str, JsonValue]:
    gap_schema = _lineage_enum_schema(
        ["missing", "not_authorized", "quarantined", "revoked", "unknown", "unreadable"]
    )
    restriction_schema = _lineage_enum_schema(
        [
            "authorization_missing",
            "category_restricted",
            "minimization",
            "never_send",
            "task_scope",
        ]
    )
    frontier_or_null: dict[str, JsonValue] = {
        "oneOf": [_lineage_frontier_schema(), {"type": "null"}]
    }
    properties: dict[str, JsonValue] = {
        "acceptance": _lineage_enum_schema(["accepted", "pending", "rejected"]),
        "child_check_id": {"oneOf": [_lineage_id_schema("event_id"), {"type": "null"}]},
        "child_check_subject_frontier": frontier_or_null,
        "child_frontier": frontier_or_null,
        "child_receipt_id": {"oneOf": [_lineage_id_schema("receipt_id"), {"type": "null"}]},
        "child_task_id": _lineage_id_schema("task_id"),
        "coverage": {"$ref": SCHEMA_NAMESPACE + "common/coverage-1.0.0.schema.json"},
        "findings": {
            "items": {"$ref": "#/$defs/child_finding"},
            "maxItems": 100,
            "type": "array",
            "uniqueItems": True,
        },
        "lineage_authority_revision": {
            "maxLength": 19,
            "pattern": _LINEAGE_POSITIVE_UINT_PATTERN,
            "type": "string",
        },
        "membership_generation": {
            "oneOf": [
                {"maxLength": 19, "pattern": _LINEAGE_POSITIVE_UINT_PATTERN, "type": "string"},
                {"type": "null"},
            ]
        },
        "origin": _lineage_enum_schema(["host_observed", "parent_minted", "self_registered"]),
        "provenance_restrictions": {
            "items": restriction_schema,
            "maxItems": 5,
            "type": "array",
            "uniqueItems": True,
        },
        "read_gap_reasons": {
            "items": gap_schema,
            "maxItems": 6,
            "type": "array",
            "uniqueItems": True,
        },
        "session_health": _lineage_enum_schema(["active", "contact_lost", "ended"]),
        "work_state": _lineage_enum_schema(
            ["abandoned", "cancelled", "closed", "open", "written_off"]
        ),
    }
    return {
        "additionalProperties": False,
        "oneOf": [
            {
                "not": {
                    "properties": {"read_gap_reasons": {"minItems": 1}},
                    "required": ["read_gap_reasons"],
                },
                "properties": {"child_frontier": {"type": "object"}},
                "required": ["child_frontier"],
            },
            {
                "properties": {
                    "child_frontier": {"type": "null"},
                    "read_gap_reasons": {"minItems": 1},
                },
                "required": ["read_gap_reasons"],
            },
        ],
        "allOf": [
            {
                "if": {"required": ["child_check_id"]},
                "then": {"required": ["child_check_subject_frontier"]},
            },
            {
                "if": {"required": ["child_check_subject_frontier"]},
                "then": {"required": ["child_check_id"]},
            },
        ],
        "properties": properties,
        "required": [
            "acceptance",
            "child_task_id",
            "coverage",
            "findings",
            "lineage_authority_revision",
            "origin",
            "session_health",
            "work_state",
        ],
        "type": "object",
    }


def _lineage_event_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Build closed event payload schemas for delegation, lifecycle, and frozen manifests."""

    name = entry.schema_name
    if name == "child-dependencies-recorded":
        raw: dict[str, object] = {
            "$defs": {
                "child_finding": _lineage_child_finding_schema(),
                "child_snapshot": _lineage_child_snapshot_schema(),
            },
            "additionalProperties": False,
            "properties": {
                "children": {
                    "items": {"$ref": "#/$defs/child_snapshot"},
                    "maxItems": 100,
                    "type": "array",
                    "uniqueItems": True,
                }
            },
            "required": ["children"],
            "type": "object",
        }
        return _normalize(raw, entry)

    child_id = _lineage_id_schema("task_id")
    reason = {
        "maxLength": 256,
        "minLength": 1,
        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:/+\-]*$",
        "type": "string",
    }
    properties: dict[str, object] = {}
    required: list[str] = []
    if name == "delegation-declared":
        properties = {
            "child_task_id": child_id,
            "depth": {"maximum": 64, "minimum": 1, "type": "integer"},
            "handle_digest": {
                "maxLength": 71,
                "minLength": 71,
                "pattern": r"^sha256:[0-9a-f]{64}$",
                "type": "string",
            },
            "membership_generation": {
                "maxLength": 19,
                "minLength": 1,
                "pattern": _LINEAGE_POSITIVE_UINT_PATTERN,
                "type": "string",
            },
            "project_id": _lineage_id_schema("project_id"),
        }
        required = ["child_task_id", "depth", "handle_digest"]
    elif name in {"delegation-cancelled", "child-rejected", "child-written-off"}:
        properties = {"child_task_id": child_id, "reason_code": reason}
        required = ["child_task_id"]
    elif name == "child-accepted":
        properties = {"child_task_id": child_id}
        required = ["child_task_id"]
    elif name in {"work-closed", "work-cancelled", "work-written-off"}:
        properties = {"reason_code": reason}
    elif name == "work-abandoned":
        properties = {"reason_code": reason, "service_stamped": {"const": True, "type": "boolean"}}
        required = ["service_stamped"]
    else:
        raise SchemaGenerationError("lineage_event_schema_unknown", entries=(entry.relative_path,))
    raw = {
        "additionalProperties": False,
        "properties": properties,
        "required": required,
        "type": "object",
    }
    if name == "delegation-declared":
        raw["allOf"] = [
            {
                "if": {
                    "anyOf": [
                        {"required": ["membership_generation"]},
                        {"required": ["project_id"]},
                    ]
                },
                "then": {"required": ["membership_generation", "project_id"]},
            }
        ]
    return _normalize(raw, entry)


def _coordination_event_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Build closed structural payloads for service context and typed dispositions."""

    event_id = _lineage_id_schema("event_id")
    task_id = _lineage_id_schema("task_id")
    project_id = {
        "pattern": r"^prj_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        "type": "string",
    }
    obligation_id = {
        "pattern": r"^obl_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        "type": "string",
    }
    finding_id = _lineage_id_schema("finding_id")
    sha256 = {"pattern": r"^sha256:[0-9a-f]{64}$", "type": "string"}
    commitment = {"pattern": r"^hmac-sha256:[0-9a-f]{64}$", "type": "string"}
    positive = {
        "maxLength": 19,
        "minLength": 1,
        "pattern": _LINEAGE_POSITIVE_UINT_PATTERN,
        "type": "string",
    }
    canonical = {
        "maxLength": 19,
        "minLength": 1,
        "pattern": _LINEAGE_UINT_PATTERN,
        "type": "string",
    }
    text_ref = {
        "additionalProperties": False,
        "properties": {
            "content_digest": sha256,
            "envelope_digest": sha256,
            "object_id": {
                "pattern": r"^obj_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
                "type": "string",
            },
            "owner_task_id": task_id,
            "plaintext_size": {"maximum": 4194304, "minimum": 0, "type": "integer"},
            "route_generation": positive,
        },
        "required": [
            "content_digest",
            "object_id",
            "owner_task_id",
            "plaintext_size",
            "route_generation",
        ],
        "type": "object",
    }
    if entry.schema_name == "coordination-context-recorded":
        raw = {
            "additionalProperties": False,
            "properties": {
                "context_digest": sha256,
                "counterpart_task_id": task_id,
                "detection_id": event_id,
                "detail_ref": text_ref,
                "gap_codes": {
                    "items": {
                        "enum": [
                            "details_truncated",
                            "not_observable",
                            "revoked",
                            "source_unavailable",
                        ],
                        "type": "string",
                    },
                    "maxItems": 4,
                    "type": "array",
                    "uniqueItems": True,
                },
                "left_task_id": task_id,
                "membership_generation": positive,
                "overlap_kind": {"enum": ["integration", "physical", "plan"], "type": "string"},
                "project_id": project_id,
                "recorded_authority_revision": sha256,
                "recipient_task_id": task_id,
                "resource_count": canonical,
                "resource_identities": {
                    "items": sha256,
                    "maxItems": 64,
                    "type": "array",
                    "uniqueItems": True,
                },
                "right_task_id": task_id,
                "source_attributable_paths": {"type": "boolean"},
                "source_repository_commitment": commitment,
                "source_route_generation": positive,
                "source_task_id": task_id,
                "source_workspace_commitment": commitment,
            },
            "required": [
                "context_digest",
                "counterpart_task_id",
                "detection_id",
                "left_task_id",
                "membership_generation",
                "overlap_kind",
                "project_id",
                "recipient_task_id",
                "resource_count",
                "resource_identities",
                "right_task_id",
                "source_attributable_paths",
                "source_repository_commitment",
                "source_route_generation",
                "source_task_id",
                "source_workspace_commitment",
            ],
            "type": "object",
        }
    elif entry.schema_name == "coordination-obligation-declared":
        raw = {
            "additionalProperties": False,
            "properties": {
                "detection_id": event_id,
                "membership_generation": positive,
                "obligation_id": obligation_id,
                "project_id": project_id,
                "recipient_task_id": task_id,
            },
            "required": [
                "detection_id",
                "membership_generation",
                "obligation_id",
                "project_id",
                "recipient_task_id",
            ],
            "type": "object",
        }
    elif entry.schema_name == "coordination-disposition-recorded":
        raw = {
            "additionalProperties": False,
            "properties": {
                "context_digest": sha256,
                "detection_id": event_id,
                "disposition": {
                    "enum": ["scope_revision", "sequencing", "shared_work"],
                    "type": "string",
                },
                "evidence_refs": {
                    "items": {
                        "pattern": r"^(?:evd|res)_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
                        "type": "string",
                    },
                    "maxItems": 64,
                    "minItems": 1,
                    "type": "array",
                    "uniqueItems": True,
                },
                "finding_id": finding_id,
                "membership_generation": positive,
                "obligation_id": obligation_id,
                "project_id": project_id,
                "recipient_task_id": task_id,
            },
            "required": [
                "detection_id",
                "disposition",
                "evidence_refs",
                "membership_generation",
                "obligation_id",
                "project_id",
                "recipient_task_id",
            ],
            "type": "object",
        }
    else:
        raise SchemaGenerationError(
            "coordination_event_schema_unknown", entries=(entry.relative_path,)
        )
    return _normalize(raw, entry)


def _lineage_session_opened_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    document = _load_versioned_template(
        entry,
        "events/session-opened-1.1.0.schema.json",
    )
    properties = cast(dict[str, JsonValue], document["properties"])
    properties.update(
        {
            "depth": {"maximum": 64, "minimum": 1, "type": "integer"},
            "origin": _lineage_enum_schema(["host_observed", "parent_minted", "self_registered"]),
            "parent_task_id": _lineage_id_schema("task_id"),
            "membership_generation": {
                "maxLength": 19,
                "minLength": 1,
                "pattern": _LINEAGE_POSITIVE_UINT_PATTERN,
                "type": "string",
            },
            "project_id": _lineage_id_schema("project_id"),
            # Optional in place while 1.2.0 is unreleased (issue #908).
            "task_statement": dict(_TASK_STATEMENT_SCHEMA),
        }
    )
    all_of = cast(list[JsonValue], document.setdefault("allOf", []))
    all_of.append(
        {
            "if": {
                "anyOf": [
                    {"required": ["depth"]},
                    {"required": ["origin"]},
                    {"required": ["parent_task_id"]},
                ]
            },
            "then": {"required": ["depth", "origin", "parent_task_id"]},
        }
    )
    all_of.append(
        {
            "if": {
                "anyOf": [
                    {"required": ["membership_generation"]},
                    {"required": ["project_id"]},
                ]
            },
            "then": {"required": ["membership_generation", "project_id"]},
        }
    )
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    document["title"] = f"Yoetz session opened {entry.schema_version}"
    return cast(dict[str, JsonValue], document)


def _start_request_v1_1_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Add delegation, self-registration, and host correlation to ``start``."""

    document = _load_versioned_template(entry, "operations/start-request-1.0.0.schema.json")
    definitions = cast(dict[str, JsonValue], document.setdefault("$defs", {}))
    definitions.update(
        {
            "attach_handle": {
                "additionalProperties": False,
                "properties": {
                    "child_task_id": _lineage_id_schema("task_id"),
                    "expires_at": {
                        "format": "date-time",
                        "pattern": r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z$",
                        "type": "string",
                    },
                    "handle": {
                        "maxLength": 256,
                        "minLength": 32,
                        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:/+\-]*$",
                        "type": "string",
                    },
                },
                "required": ["child_task_id", "expires_at", "handle"],
                "type": "object",
            },
            "host_correlation": {
                "maxLength": 256,
                "minLength": 1,
                "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:/+\-]*$",
                "type": "string",
            },
            "task_id": _lineage_id_schema("task_id"),
        }
    )
    properties = cast(dict[str, JsonValue], document["properties"])
    properties.update(
        {
            "attach_handle": {"$ref": "#/$defs/attach_handle"},
            "correlation_id": {"$ref": "#/$defs/host_correlation"},
            "mode": {"enum": ["attach", "create", "create_or_attach", "delegate"]},
            "parent_session_id": {"$ref": "#/$defs/session_id"},
            "parent_tool_call_id": {"$ref": "#/$defs/host_correlation"},
            "session_id": {"$ref": "#/$defs/session_id"},
            "subagent_id": {"$ref": "#/$defs/host_correlation"},
            # The optional agent-transcribed task statement (issue #908), added in place while
            # 1.1.0 is unreleased; absent requests keep their exact shape.
            "task_statement": dict(_TASK_STATEMENT_SCHEMA),
        }
    )
    rules = cast(list[JsonValue], document.setdefault("allOf", []))
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        condition = rule.get("if")
        then = rule.get("then")
        if not isinstance(condition, dict) or not isinstance(then, dict):
            continue
        condition_properties = condition.get("properties")
        if not isinstance(condition_properties, dict):
            continue
        mode = condition_properties.get("mode")
        if isinstance(mode, dict) and mode.get("const") == "attach":
            any_of = cast(dict[str, JsonValue], then).get("anyOf")
            if isinstance(any_of, list):
                any_of.append({"required": ["attach_handle"]})
            break
    rules.extend(
        [
            {
                "if": {"properties": {"mode": {"const": "delegate"}}, "required": ["mode"]},
                "then": {
                    "required": ["session_id"],
                    "not": {
                        "anyOf": [
                            {"required": ["parent_session_id"]},
                            {"required": ["attach_handle"]},
                        ]
                    },
                },
            },
            {
                "if": {"required": ["attach_handle"]},
                "then": {"properties": {"mode": {"const": "attach"}}},
            },
            {
                "if": {"required": ["parent_session_id"]},
                "then": {"properties": {"mode": {"enum": ["create", "create_or_attach"]}}},
            },
        ]
    )
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    document["title"] = f"Yoetz start request {entry.schema_version}"
    return cast(dict[str, JsonValue], document)


def _start_result_v1_1_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Extend the reviewed start result with the delegated-child return contract."""

    predecessor = _RegistryEntry(
        "operations/start-result-1.0.0.schema.json",
        "start-result",
        "1.0.0",
        "request_result",
        "MCP output",
        entry.loader,
    )
    document = _start_result_schema(predecessor)
    definitions = cast(dict[str, JsonValue], document["$defs"])
    success = cast(dict[str, JsonValue], definitions["success"])
    properties = cast(dict[str, JsonValue], success["properties"])
    properties.update(
        {
            "acceptance": {"enum": ["accepted", "pending", "rejected"]},
            "attach_handle": {"$ref": "#/$defs/attach_handle"},
            "depth": {
                "oneOf": [
                    {
                        "maxLength": 19,
                        "minLength": 1,
                        "pattern": _LINEAGE_POSITIVE_UINT_PATTERN,
                        "type": "string",
                    },
                    {"type": "null"},
                ]
            },
            "origin": {"enum": ["host_observed", "parent_minted", "self_registered"]},
            "parent_task_id": {"oneOf": [_lineage_id_schema("task_id"), {"type": "null"}]},
        }
    )
    outcome = cast(dict[str, JsonValue], properties["outcome"])
    outcome["enum"] = ["attached", "created", "delegated", "replayed"]
    # The additive fields are omitted for ordinary create/attach results and therefore remain
    # optional at the top level.  Their delegated branch is made complete below.
    success.setdefault("allOf", [])
    cast(list[JsonValue], success["allOf"]).extend(
        [
            {
                "if": {
                    "anyOf": [
                        {"required": ["acceptance"]},
                        {"required": ["depth"]},
                        {"required": ["origin"]},
                        {"required": ["parent_task_id"]},
                    ]
                },
                "then": {"required": ["acceptance", "depth", "origin", "parent_task_id"]},
            },
            {
                "if": {"properties": {"outcome": {"const": "delegated"}}, "required": ["outcome"]},
                "then": {
                    "properties": {
                        "acceptance": {"const": "accepted"},
                        "origin": {"const": "parent_minted"},
                    },
                    "required": [
                        "acceptance",
                        "attach_handle",
                        "depth",
                        "origin",
                        "parent_task_id",
                    ],
                },
            },
            {
                "if": {"required": ["attach_handle"]},
                "then": {"properties": {"outcome": {"const": "delegated"}}},
            },
        ]
    )
    definitions["attach_handle"] = {
        "additionalProperties": False,
        "properties": {
            "child_task_id": _lineage_id_schema("task_id"),
            "expires_at": {
                "format": "date-time",
                "pattern": r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z$",
                "type": "string",
            },
            "handle": {
                "maxLength": 256,
                "minLength": 32,
                "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:/+\-]*$",
                "type": "string",
            },
        },
        "required": ["child_task_id", "expires_at", "handle"],
        "type": "object",
    }
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    _admit_recorded_policy_identities(document)
    document["title"] = f"Yoetz start result {entry.schema_version}"
    return document


def _todo_state_schema() -> dict[str, JsonValue]:
    """The closed finding to-do states of issue #905."""

    return {
        "enum": [
            "acknowledged_not_done",
            "disputed_after_rebuttal",
            "open",
            "rejection_accepted",
            "self_verified",
            "verified_resolved",
        ],
        "type": "string",
    }


def _attempt_budget_schema() -> dict[str, JsonValue]:
    """The owner's per-item review-round budget, 1 through 50, as a canonical string."""

    return {"pattern": "^(?:[1-9]|[1-4][0-9]|50)$", "type": "string"}


def _check_result_v1_3_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Add the frozen child preview and advisory coordination branches to ``check``."""

    document = _load_versioned_template(
        entry,
        "operations/check-result-1.2.0.schema.json",
    )
    definitions = cast(dict[str, JsonValue], document["$defs"])
    binding = cast(dict[str, JsonValue], definitions["semantic_binding"])
    _add_review_input_manifest_to_check_result(document)
    _admit_current_launcher_heads(definitions)
    for branch in cast(list[JsonValue], binding["oneOf"]):
        if not isinstance(branch, dict):
            continue
        branch_properties = branch.get("properties")
        branch_required = branch.get("required")
        if not isinstance(branch_properties, dict) or not isinstance(branch_required, list):
            continue
        provenance_shape = branch_properties.get("semantic_provenance")
        # The current result serializer omits nullable provenance for outcomes where no semantic
        # evidence is required.  Keep the required field on provenance-bearing branches, while
        # allowing omission on null-only and failed/coordinator branches.
        if isinstance(provenance_shape, dict):
            if provenance_shape.get("type") == "null" or "oneOf" in provenance_shape:
                branch_required[:] = [
                    item for item in branch_required if item != "semantic_provenance"
                ]
    definitions["code"] = {
        "maxLength": 128,
        "pattern": r"^[a-z][a-z0-9_]{0,127}$",
        "type": "string",
    }
    frontier_ref = SCHEMA_NAMESPACE + "common/frontier-1.0.0.schema.json"
    definitions["child_preview_item"] = {
        "additionalProperties": False,
        "properties": {
            "acceptance": {
                "enum": ["accepted", "pending", "rejected"],
                "type": "string",
            },
            "blocking_conditions": {
                "items": {"$ref": "#/$defs/code"},
                "maxItems": 64,
                "type": "array",
                "uniqueItems": True,
            },
            "child_task_id": {"$ref": "#/$defs/task_id"},
            "origin": {
                "enum": ["host_observed", "parent_minted", "self_registered"],
                "type": "string",
            },
            "rollup_state": {
                "enum": [
                    "annotation",
                    "blocked",
                    "clean",
                    "incomplete",
                    "open_gap",
                    "unavailable",
                ],
                "type": "string",
            },
            "session_health": {
                "enum": ["active", "contact_lost", "ended"],
                "type": "string",
            },
            "work_state": {
                "enum": ["abandoned", "cancelled", "closed", "open", "written_off"],
                "type": "string",
            },
        },
        "required": [
            "acceptance",
            "blocking_conditions",
            "child_task_id",
            "origin",
            "rollup_state",
            "session_health",
            "work_state",
        ],
        "type": "object",
    }
    definitions["children_preview"] = {
        "additionalProperties": False,
        "properties": {
            "items": {
                "items": {"$ref": "#/$defs/child_preview_item"},
                "maxItems": 64,
                "type": "array",
                "uniqueItems": True,
            },
            "label": {"enum": ["preview", "recorded"], "type": "string"},
            "tested_manifest_frontier": {"oneOf": [{"$ref": frontier_ref}, {"type": "null"}]},
        },
        "required": ["items", "label", "tested_manifest_frontier"],
        "type": "object",
    }
    definitions["advisory_note"] = {
        "additionalProperties": False,
        "properties": {
            "count": {
                "maxLength": 19,
                "minLength": 1,
                "pattern": _LINEAGE_POSITIVE_UINT_PATTERN,
                "type": "string",
            },
            "kind": {
                "enum": ["duplicate_finding", "live_member_present"],
                "type": "string",
            },
            "project_id": {
                "pattern": r"^prj_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
                "type": "string",
            },
            "task_ids": {
                "items": {"$ref": "#/$defs/task_id"},
                "maxItems": 64,
                "type": "array",
                "uniqueItems": True,
            },
        },
        "required": ["count", "kind", "project_id", "task_ids"],
        "type": "object",
    }
    success = cast(dict[str, JsonValue], definitions["success"])
    properties = cast(dict[str, JsonValue], success["properties"])
    # Current public serialization omits nullable semantic provenance when no semantic attempt was
    # requested.  The frozen 1.1 predecessor required an explicit null marker; this successor
    # carries the additive omission contract used by CheckSuccessModel.optional_non_null_fields.
    required = cast(list[JsonValue], success["required"])
    if "semantic_provenance" in required:
        required.remove("semantic_provenance")
    properties["children"] = {"oneOf": [{"$ref": "#/$defs/children_preview"}, {"type": "null"}]}
    properties["advisory_notes"] = {
        "items": {"$ref": "#/$defs/advisory_note"},
        "maxItems": 64,
        "type": "array",
        "uniqueItems": True,
    }
    from finishup.protocol.models import MISSING_ITEM_AVAILABILITIES

    # Issue #907: what an insufficient_packet review named as missing, as a check limitation.
    # Additive and optional on this unreleased version, like advisory_notes above.
    definitions["missing_item"] = {
        "additionalProperties": False,
        "properties": {
            "availability": {
                # tb4n1 D1 (#983): FinishUP-limit classes join the closed vocabulary; their
                # ``yoetz_limit_*`` values are frozen legacy identifiers (ADR-048).
                "enum": sorted(MISSING_ITEM_AVAILABILITIES, key=str.encode),
                "type": "string",
            },
            "kind": {
                "enum": [
                    "command_identity",
                    "current_diff_for_path",
                    "other",
                    "plan_or_claim_text",
                    "prior_finding_context",
                    "task_statement",
                    "verification_output",
                ],
                "type": "string",
            },
            "target_refs": {
                "items": {"$ref": "#/$defs/subject_id"},
                "maxItems": 4,
                "type": "array",
                "uniqueItems": True,
            },
        },
        "required": ["availability", "kind", "target_refs"],
        "type": "object",
    }
    properties["missing_for_assessment"] = {
        "items": {"$ref": "#/$defs/missing_item"},
        "maxItems": 8,
        "type": "array",
        "uniqueItems": True,
    }
    # Issue #920: bounded opaque item identities omitted by the heuristic never-send class.
    definitions["semantic_withheld_item"] = {
        "additionalProperties": False,
        "properties": {
            "item_id": {
                "maxLength": 128,
                "minLength": 1,
                "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
                "type": "string",
            },
            "reason": {"const": "never_send_heuristic"},
        },
        "required": ["item_id", "reason"],
        "type": "object",
    }
    properties["semantic_withheld_items"] = {
        "items": {"$ref": "#/$defs/semantic_withheld_item"},
        "maxItems": 64,
        "type": "array",
        "uniqueItems": True,
    }
    # Issue #905: the task's findings as a to-do list after this check (structural only).
    definitions["todo_state"] = _todo_state_schema()
    definitions["checklist_item"] = {
        "additionalProperties": False,
        "properties": {
            "finding_id": {"$ref": "#/$defs/finding_id"},
            "review_rounds": {"$ref": "#/$defs/canonical_uint"},
            "todo_state": {"$ref": "#/$defs/todo_state"},
        },
        "required": ["finding_id", "todo_state", "review_rounds"],
        "type": "object",
    }
    definitions["finding_checklist"] = {
        "additionalProperties": False,
        "properties": {
            "attempt_budget": _attempt_budget_schema(),
            "counts": {
                "additionalProperties": False,
                "properties": {
                    name: {"$ref": "#/$defs/canonical_uint"}
                    for name in (
                        "acknowledged_not_done",
                        # Issue #1020: optional, emitted only when non-zero.
                        "disputed_after_rebuttal",
                        "open",
                        "open_at_budget",
                        "rejection_accepted",
                        "self_verified",
                        "verified_resolved",
                    )
                },
                "required": [
                    "acknowledged_not_done",
                    "open",
                    "open_at_budget",
                    "rejection_accepted",
                    "self_verified",
                    "verified_resolved",
                ],
                "type": "object",
            },
            "items": {
                "items": {"$ref": "#/$defs/checklist_item"},
                "maxItems": 100,
                "type": "array",
                "uniqueItems": True,
            },
            "next": {
                "enum": ["decide_at_budget", "request_receipt", "work_open_findings"],
                "type": "string",
            },
        },
        "required": ["attempt_budget", "counts", "items", "next"],
        "type": "object",
    }
    properties["finding_checklist"] = {"$ref": "#/$defs/finding_checklist"}
    policy_execution = cast(dict[str, JsonValue], definitions["policy_execution"])
    policy_execution_properties = cast(dict[str, JsonValue], policy_execution["properties"])
    policy_id = cast(dict[str, JsonValue], policy_execution_properties["policy_id"])
    policy_id_values = cast(list[JsonValue], policy_id["enum"])
    if "coordination" not in policy_id_values:
        policy_id_values.append("coordination")
        policy_id_values.sort(key=lambda item: str(item).encode("ascii"))
    policy_executions = cast(dict[str, JsonValue], properties["policy_executions"])
    policy_executions["maxItems"] = 3
    projected_finding = cast(dict[str, JsonValue], definitions["projected_finding"])
    projected_properties = cast(dict[str, JsonValue], projected_finding["properties"])
    projected_kind = cast(dict[str, JsonValue], projected_properties["kind"])
    projected_kind_values = cast(list[JsonValue], projected_kind["enum"])
    if "coordination_overlap" not in projected_kind_values:
        projected_kind_values.append("coordination_overlap")
        projected_kind_values.sort(key=lambda item: str(item).encode("ascii"))
    projected_policy = cast(dict[str, JsonValue], projected_properties["policy_id"])
    projected_policy_values = cast(list[JsonValue], projected_policy["enum"])
    if "coordination" not in projected_policy_values:
        projected_policy_values.append("coordination")
        projected_policy_values.sort(key=lambda item: str(item).encode("ascii"))
    version_slice = cast(dict[str, JsonValue], definitions["version_slice"])
    version_properties = cast(dict[str, JsonValue], version_slice["properties"])
    version_packs = cast(dict[str, JsonValue], version_properties["policy_packs"])
    version_items = cast(dict[str, JsonValue], version_packs["items"])
    version_values = cast(list[JsonValue], version_items["enum"])
    if "coordination/0.1.0" not in version_values:
        version_values.append("coordination/0.1.0")
        version_values.sort(key=lambda item: str(item).encode("ascii"))
    version_packs["maxItems"] = 3
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    document["title"] = f"Yoetz check result {entry.schema_version}"
    return document


def _add_semantic_route_required(properties: dict[str, JsonValue]) -> None:
    """Issue #986: whether the check's route required AI-powered review (unreleased 1.4.0).

    Optional and additive. Writers emit only ``false`` (the route did not require review, so
    ``semantic_review_not_requested`` is a disclosure); a requiring route and every older check
    omit it, which keeps their bytes and the blocking default.
    """

    properties["semantic_route_required"] = {"type": "boolean"}


def _add_check_review_mode(
    definitions: dict[str, JsonValue], properties: dict[str, JsonValue]
) -> None:
    """ADR-049: the conversation review mode one check ran in and why (unreleased 1.4.0).

    Optional and additive: closed tokens and one event id, never prose. ``local_reason`` appears
    only on a local check that was asked to run AI-powered review; ``switch_event_id`` exactly
    when the conversation's own switch chose the mode.
    """

    definitions["check_review_mode"] = {
        "additionalProperties": False,
        "allOf": [
            {
                "if": {"properties": {"source": {"const": "conversation_switch"}}},
                "then": {"required": ["switch_event_id"]},
                "else": {"not": {"required": ["switch_event_id"]}},
            },
            {
                "if": {"required": ["local_reason"]},
                "then": {"properties": {"mode": {"const": "local"}}},
            },
        ],
        "properties": {
            "local_reason": {
                "enum": [
                    "ai_review_not_set_up",
                    "owner_local_only",
                    "review_disabled",
                    "route_local_only",
                ],
                "type": "string",
            },
            "mode": {"enum": ["ai_powered", "local"], "type": "string"},
            "source": {
                "enum": ["check_request", "conversation_default", "conversation_switch"],
                "type": "string",
            },
            "switch_event_id": {
                "pattern": (
                    "^evt_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
                ),
                "type": "string",
            },
        },
        "required": ["mode", "source"],
        "type": "object",
    }
    properties["review_mode"] = {"$ref": "#/$defs/check_review_mode"}


def _fact_lineage_definition() -> dict[str, JsonValue]:
    """ADR-045: where one derived fact came from. Closed tokens, counts and ids; never a path."""

    uint: dict[str, JsonValue] = {"$ref": "#/$defs/canonical_uint"}
    # Inline id patterns: the check result's ``$defs`` carry no ``event_id`` / ``obligation_id``.
    event_ref: dict[str, JsonValue] = {
        "pattern": r"^evt_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        "type": "string",
    }
    obligation_ref: dict[str, JsonValue] = {
        "pattern": r"^obl_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        "type": "string",
    }
    return {
        "additionalProperties": False,
        "properties": {
            "accepted_by": event_ref,
            "basis": {"enum": ["delivered", "present", "verified"], "type": "string"},
            "check_event_id": event_ref,
            "code": {"$ref": "#/$defs/code"},
            "frontier": uint,
            "item_index": {"pattern": r"^(?:[0-9]|[1-5][0-9]|6[0-3])$", "type": "string"},
            "now_lines": uint,
            "now_size_bytes": uint,
            "obligation_id": obligation_ref,
            "prior_event_id": event_ref,
            "prior_frontier": uint,
            "prior_lines": uint,
            "prior_size_bytes": uint,
            "proof": {"enum": ["earlier_check", "observed_run", "task_base"], "type": "string"},
            "rule": {
                "enum": [
                    "deliverable_path_history",
                    "deliverable_read",
                    "edit_after_verification_run",
                    "planned_command_match",
                    "planned_command_unmatched",
                ],
                "type": "string",
            },
            "source_event_ids": {
                "items": event_ref,
                "maxItems": 8,
                "type": "array",
                "uniqueItems": True,
            },
            "state": {
                "enum": [
                    "accepted",
                    "edited_after",
                    "emptied",
                    "failed",
                    "matched_agent_link",
                    "matched_exact",
                    "matched_flags",
                    "matched_normalized",
                    "matched_prefix",
                    "removed",
                    "stale",
                    "truncated",
                    "unmatched",
                    "unreviewable",
                ],
                "type": "string",
            },
        },
        "required": ["code", "rule", "state"],
        "type": "object",
    }


def _fact_lineage_array() -> dict[str, JsonValue]:
    return {
        "items": {"$ref": "#/$defs/fact_lineage"},
        "maxItems": 64,
        "type": "array",
        "uniqueItems": True,
    }


def _add_deliverable_states(
    definitions: dict[str, JsonValue], properties: dict[str, JsonValue]
) -> None:
    """ADR-045 (tb4n3 RC-5): how each declared output file stood at a check. Optional/additive.

    Sizes, counts, closed tokens, ids and a keyed path commitment for the declared file itself,
    never its path. ``undeclared_references`` (tb4n4, #1044, added in place on the unreleased
    1.4.0) is the one path text: the root-relative files the change created that this source
    deliverable names and no item declares, so the receipt and the Stop gate can name them.
    ``undeclared_reference_ambiguous`` (tb4n5, ADR-035 amendment, also in place) counts created
    files the deliverable names only by an ambiguous file name; never a name.
    ``undeclared_references_created_in_task`` is read-compatibility only: intermediate builds
    (857a712de) wrote it before the provenance was withdrawn, so those ledgers still decode; no
    build produces it now and it grants nothing. Absent on a check that read no declared output
    file, so those checks keep their bytes.
    """

    count: dict[str, JsonValue] = {"maximum": 9007199254740991, "minimum": 0, "type": "integer"}
    event_ref: dict[str, JsonValue] = {
        "pattern": r"^evt_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        "type": "string",
    }
    definitions["deliverable_state"] = {
        "additionalProperties": False,
        "properties": {
            "accepted_by": dict(event_ref),
            "base_lines": dict(count),
            "basis": {"enum": ["delivered", "present", "verified"], "type": "string"},
            "change": {
                "enum": ["emptied", "removed", "truncated", "unchanged"],
                "type": "string",
            },
            "item_index": {"maximum": 63, "minimum": 0, "type": "integer"},
            "lines": dict(count),
            "obligation_id": {
                "pattern": (
                    r"^obl_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
                ),
                "type": "string",
            },
            "path_key": {"pattern": r"^hmac-sha256:[0-9a-f]{64}$", "type": "string"},
            "prior_event_id": dict(event_ref),
            "prior_frontier": dict(count),
            "prior_lines": dict(count),
            "prior_size_bytes": dict(count),
            "proof": {"enum": ["earlier_check", "task_base"], "type": "string"},
            "size_bytes": dict(count),
            "undeclared_reference_count": {
                "maximum": 9007199254740991,
                "minimum": 1,
                "type": "integer",
            },
            "undeclared_references": {
                "items": {
                    "maxLength": 256,
                    "minLength": 1,
                    "pattern": "^[^\\u0000-\\u001f\\u007f/][^\\u0000-\\u001f\\u007f]*$",
                    "type": "string",
                },
                "maxItems": 8,
                "minItems": 1,
                "type": "array",
                "uniqueItems": True,
            },
            "undeclared_reference_ambiguous": {
                "maximum": 9007199254740991,
                "minimum": 1,
                "type": "integer",
            },
            # Read-compatibility only (857a712de wrote it; nothing produces it now).
            "undeclared_references_created_in_task": {"const": True},
            "unreviewable": {"const": True},
        },
        "required": ["basis", "item_index", "obligation_id"],
        "type": "object",
    }
    properties["deliverable_states"] = {
        "items": {"$ref": "#/$defs/deliverable_state"},
        "maxItems": 64,
        "type": "array",
        "uniqueItems": True,
    }


def _add_semantic_redacted_values(
    definitions: dict[str, JsonValue],
    properties: dict[str, JsonValue],
    *,
    min_items: int = 0,
) -> None:
    """PL2-1 (issue #982): item refs and 1-based line numbers, never values. Additive/optional."""

    opaque: dict[str, JsonValue] = {
        "maxLength": 128,
        "minLength": 1,
        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
        "type": "string",
    }
    definitions["semantic_redacted_value"] = {
        "additionalProperties": False,
        "properties": {
            "disposition": {"enum": ["item_withheld", "value_replaced"], "type": "string"},
            "item_id": opaque,
            "lines": {
                "items": {"maximum": 2147483647, "minimum": 1, "type": "integer"},
                "maxItems": 32,
                "type": "array",
                "uniqueItems": True,
            },
            "source_ref": dict(opaque),
        },
        "required": ["disposition", "item_id", "lines"],
        "type": "object",
    }
    array: dict[str, JsonValue] = {
        "items": {"$ref": "#/$defs/semantic_redacted_value"},
        "maxItems": 64,
        "type": "array",
        "uniqueItems": True,
    }
    if min_items:
        array["minItems"] = min_items
    properties["semantic_redacted_values"] = array


def _check_result_v1_4_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Add the public Part 2 review fields to the new check-result version.

    The review prose is represented as either bounded text or the existing finding-summary
    omission marker. Structural verdicts and refs remain visible under the agent projection,
    while the prose leaves are replaced by the privacy gateway when the caller lacks access.
    """

    document = _check_result_v1_3_schema(entry)
    definitions = cast(dict[str, JsonValue], document["$defs"])
    success = cast(dict[str, JsonValue], definitions["success"])
    properties = cast(dict[str, JsonValue], success["properties"])
    content_text = {"$ref": "#/$defs/content_text"}
    finding_omission = {"$ref": "#/$defs/finding_omission"}
    definitions["finding_challenge"] = {
        "additionalProperties": False,
        "properties": {
            "alternative_interpretation": {"oneOf": [content_text, finding_omission]},
            "discrepancy": {"oneOf": [content_text, finding_omission]},
            "requested_next_step": {
                "enum": [
                    "act",
                    "answer_question",
                    "dispute_with_evidence",
                    "provide_evidence",
                    "revise_claim",
                    "state_unresolved_limitation",
                ],
                "type": "string",
            },
            "snippet": {"oneOf": [content_text, finding_omission, {"type": "null"}]},
            "uncertainty": {"oneOf": [content_text, finding_omission]},
        },
        "required": [
            "alternative_interpretation",
            "discrepancy",
            "requested_next_step",
            "uncertainty",
        ],
        "type": "object",
    }
    definitions["verified_item"] = {
        "additionalProperties": False,
        "allOf": [
            {
                "if": {
                    "properties": {"verdict": {"const": "not_assessable"}},
                    "required": ["verdict"],
                },
                "then": {"not": {"required": ["snippet"]}},
            },
            {
                "if": {
                    "properties": {"verdict": {"enum": ["not_supported", "supported"]}},
                    "required": ["verdict"],
                },
                "then": {"required": ["snippet"]},
            },
        ],
        "properties": {
            "cited_refs": {
                "items": {"$ref": "#/$defs/subject_id"},
                "maxItems": 16,
                "minItems": 1,
                "type": "array",
                "uniqueItems": True,
            },
            "requirement_or_claim": {"oneOf": [content_text, finding_omission]},
            "snippet": {"oneOf": [content_text, finding_omission]},
            "verdict": {
                "enum": ["not_assessable", "not_supported", "supported"],
                "type": "string",
            },
        },
        "required": ["cited_refs", "requirement_or_claim", "verdict"],
        "type": "object",
    }
    properties["semantic_conclusion"] = {
        "enum": ["challenges_returned", "insufficient_packet", "no_material_discrepancy"],
        "type": "string",
    }
    properties["review_summary"] = {"oneOf": [content_text, finding_omission]}
    definitions["check_totals"] = _check_totals_schema()
    properties["totals"] = {"$ref": "#/$defs/check_totals"}
    # Issue #963: the task-level continuation is separate from the finding-only checklist.
    # Keep it additive on the active 1.4.0 contract; the frozen 1.3.0 shape remains unchanged.
    definitions["overall_next"] = {
        "additionalProperties": False,
        "allOf": [
            {
                "if": {
                    "properties": {
                        "action": {"enum": ["work_open_findings", "review_recorded_work"]}
                    },
                    "required": ["action"],
                },
                "then": {
                    "properties": {
                        "status": {"const": "action_required"},
                        "target_refs": {"minItems": 1},
                    }
                },
            },
            {
                "if": {
                    "properties": {"action": {"const": "supply_missing_input"}},
                    "required": ["action"],
                },
                "then": {"properties": {"status": {"const": "action_required"}}},
            },
            {
                "if": {
                    "properties": {"action": {"const": "request_receipt"}},
                    "required": ["action"],
                },
                "then": {"properties": {"target_refs": {"maxItems": 0}}},
            },
            {
                "if": {
                    "properties": {"acknowledged_incomplete_endpoint": {"const": "receipt"}},
                    "required": ["acknowledged_incomplete_endpoint"],
                },
                "then": {
                    "properties": {
                        "action": {"const": "request_receipt"},
                        "status": {"const": "ready_with_limitations"},
                    }
                },
            },
        ],
        "properties": {
            "action": {
                "enum": [
                    "supply_missing_input",
                    "work_open_findings",
                    "review_recorded_work",
                    "request_receipt",
                ],
                "type": "string",
            },
            "acknowledged_incomplete_endpoint": {"oneOf": [{"const": "receipt"}, {"type": "null"}]},
            "status": {
                "enum": ["action_required", "ready_with_limitations", "ready"],
                "type": "string",
            },
            "target_refs": {
                "items": {"$ref": "#/$defs/subject_id"},
                "maxItems": 64,
                "type": "array",
                "uniqueItems": True,
            },
        },
        "required": ["action", "status", "target_refs"],
        "type": "object",
    }
    properties["overall_next"] = {"$ref": "#/$defs/overall_next"}
    # Issue #1012: additive on the unreleased 1.4.0 contract, present only when the request set
    # ``await_observations``. ``complete`` and ``unavailable`` carry a zero count.
    definitions["observations_awaited"] = {
        "additionalProperties": False,
        "allOf": [
            {
                "if": {
                    "properties": {"state": {"enum": ["complete", "unavailable"]}},
                    "required": ["state"],
                },
                "then": {"properties": {"pending_count": {"const": "0"}}},
            },
            {
                "if": {
                    "properties": {"state": {"const": "bounded_timeout"}},
                    "required": ["state"],
                },
                "then": {"properties": {"pending_count": {"not": {"const": "0"}}}},
            },
        ],
        "properties": {
            "pending_count": {"$ref": "#/$defs/canonical_uint"},
            "state": {
                "enum": ["bounded_timeout", "complete", "unavailable"],
                "type": "string",
            },
        },
        "required": ["pending_count", "state"],
        "type": "object",
    }
    properties["observations_awaited"] = {"$ref": "#/$defs/observations_awaited"}
    properties["verified"] = {
        "items": {"$ref": "#/$defs/verified_item"},
        "maxItems": 64,
        "type": "array",
        "uniqueItems": True,
    }
    projected_finding = cast(dict[str, JsonValue], definitions["projected_finding"])
    projected_properties = cast(dict[str, JsonValue], projected_finding["properties"])
    projected_properties["challenge"] = {"$ref": "#/$defs/finding_challenge"}
    kind = cast(dict[str, JsonValue], projected_properties["kind"])
    values = cast(list[JsonValue], kind["enum"])
    for value in (
        "agent_criterion_unmet",
        "code_defect",
        "task_requirement_unmet",
    ):
        if value not in values:
            values.append(value)
    values.sort(key=lambda item: str(item).encode("ascii"))
    _add_semantic_redacted_values(definitions, properties)
    _add_semantic_route_required(properties)
    _add_check_review_mode(definitions, properties)
    _add_check_closure_verdict(definitions)
    definitions["fact_lineage"] = _fact_lineage_definition()
    properties["fact_lineage"] = _fact_lineage_array()
    _add_check_inspection(document)
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    _admit_recorded_policy_identities(document)
    document["title"] = f"Yoetz check result {entry.schema_version}"
    return document


def _check_result_v1_5_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Admit the pre-edit deferral reason on check-result 1.5.0 (n6 item 4)."""

    document = _check_result_v1_4_schema(entry)
    _admit_deferred_before_first_edit(document)
    _add_check_agent_next(document)
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    # New document (ADR-048): prose title uses FinishUP; the yoetz.dev $id stays frozen.
    document["title"] = f"FinishUP check result {entry.schema_version}"
    return document


def _check_result_v1_6_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """#1118: check-result 1.6.0 is 1.5.0 plus the optional reviewer record on a success."""

    document = _check_result_v1_5_schema(entry)
    _admit_stopped_review(document)
    _add_check_reviewer(document)
    _add_test_check_to_review_input_manifest(document)
    definitions = cast(dict[str, JsonValue], document["$defs"])
    # Decision findings belong to the current contract; historical 1.4/1.5 bytes stay frozen.
    projected = cast(dict[str, JsonValue], definitions["projected_finding"])
    projected_properties = cast(dict[str, JsonValue], projected["properties"])
    kind = cast(dict[str, JsonValue], projected_properties["kind"])
    kinds = cast(list[JsonValue], kind["enum"])
    kinds.append("decision_needed")
    kinds.sort(key=lambda item: str(item).encode("ascii"))
    checklist = cast(dict[str, JsonValue], definitions["finding_checklist"])
    checklist_properties = cast(dict[str, JsonValue], checklist["properties"])
    cast(list[JsonValue], cast(dict[str, JsonValue], checklist_properties["next"])["enum"]).append(
        "follow_overall_next"
    )
    # Issue #1209: status's open fix-or-decline items on the inspection's ``remaining`` (optional,
    # omitted when none); historical 1.4/1.5 bytes stay frozen.
    remaining = cast(dict[str, JsonValue], definitions["inspection_remaining"])
    inspected_obligation = cast(dict[str, JsonValue], definitions["inspection_obligation"])
    cast(dict[str, JsonValue], remaining["properties"])["fix_or_decline"] = _fix_or_decline_array(
        json.loads(
            json.dumps(
                cast(dict[str, JsonValue], inspected_obligation["properties"])["obligation_id"]
            )
        )
    )
    success = cast(dict[str, JsonValue], definitions["success"])
    cast(dict[str, JsonValue], success["properties"])["review_guidance"] = {
        "type": "string",
        "const": ReviewGuidance.MATERIAL_CONCERNS.value,
    }
    cast(dict[str, JsonValue], success["properties"])["closure_readiness"] = {
        "$ref": SCHEMA_NAMESPACE
        + "operations/status-result-1.4.0.schema.json#/$defs/closure_readiness"
    }
    cast(dict[str, JsonValue], success["properties"])["review_delivery"] = {
        "oneOf": [
            {"type": "string", "minLength": 1, "maxLength": 4096},
            {"$ref": "#/$defs/finding_omission"},
        ]
    }
    cast(dict[str, JsonValue], success["properties"])["correctness_advisories"] = (
        _check_correctness_advisories_schema()
    )
    cast(dict[str, JsonValue], success["properties"])["agent_status_line"] = dict(
        _AGENT_STATUS_LINE
    )
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    document["title"] = f"FinishUP check result {entry.schema_version}"
    return document


def _admit_stopped_review(document: dict[str, JsonValue]) -> None:
    """A requested review stopped before dispatch; no new provider provenance (#1149)."""

    definitions = cast(dict[str, JsonValue], document["$defs"])
    binding = cast(dict[str, JsonValue], definitions["semantic_binding"])
    branches = cast(list[JsonValue], binding["oneOf"])
    template = next(
        item
        for item in branches
        if isinstance(item, dict)
        and cast(
            dict[str, JsonValue], cast(dict[str, JsonValue], item["properties"])["semantic_reason"]
        ).get("const")
        == "deterministic_mode"
    )
    clone = copy.deepcopy(template)
    properties = cast(dict[str, JsonValue], clone["properties"])
    cast(dict[str, JsonValue], properties["semantic_status"])["const"] = "unavailable"
    cast(dict[str, JsonValue], properties["semantic_reason"])["const"] = "round_limit_unassessable"
    branches.append(clone)
    holder = (
        cast(dict[str, JsonValue], document["properties"])
        if "success" not in definitions
        else cast(
            dict[str, JsonValue], cast(dict[str, JsonValue], definitions["success"])["properties"]
        )
    )
    reasons = cast(list[JsonValue], cast(dict[str, JsonValue], holder["semantic_reason"])["enum"])
    reasons.append("round_limit_unassessable")
    reasons.sort(key=lambda item: str(item).encode("ascii"))
    if "success" not in definitions:
        # Historical recorded-review templates require a completed semantic conclusion. A
        # stopped 1.6.0 check has none; relax only this pair, keeping completed reviews exact.
        holder["semantic_status"] = {"enum": ["succeeded", "unavailable"], "type": "string"}
        cast(list[JsonValue], document["required"]).remove("semantic_conclusion")
        cast(list[JsonValue], document["allOf"]).append(
            {
                "oneOf": [
                    {
                        "properties": {"semantic_status": {"const": "succeeded"}},
                        "required": ["semantic_conclusion"],
                    },
                    {
                        "properties": {
                            "semantic_status": {"const": "unavailable"},
                            "semantic_reason": {"const": "round_limit_unassessable"},
                        },
                        "not": {
                            "anyOf": [
                                {"required": ["semantic_conclusion"]},
                                {"required": ["reviewer"]},
                            ]
                        },
                    },
                ]
            }
        )


# W6 (ADR-043 amendment): the service-composed lead of a check result, one printable ASCII line.
_AGENT_NEXT_TEXT: Final[Mapping[str, JsonValue]] = MappingProxyType(
    {"maxLength": 2048, "minLength": 1, "pattern": "^[ -~]+$", "type": "string"}
)


# #1139: the counted decision-point ledger line (``domain.decision_status``), fixed words, counts
# and service-minted obligation ids only. Additive and optional on the unreleased check-result
# 1.6.0 and status-result 1.4.0 (in place), so 1.7.0 and 1.5.0 inherit it.
_AGENT_STATUS_LINE: Final[Mapping[str, JsonValue]] = MappingProxyType(
    {
        "maxLength": 2048,
        "minLength": 1,
        "pattern": (
            r"^Ledger \(records, not correctness\): [a-z0-9_ ,;:()+-]{1,1900}"
            r"per-obligation detail: status view=obligations\.$"
        ),
        "type": "string",
    }
)


def _add_check_agent_next(document: dict[str, JsonValue]) -> None:
    """Admit ``agent_next`` on the check success branch (W6; unreleased 1.5.0, in place).

    Closed sentences and admitted ids the service composes from ``overall_next`` and
    ``missing_for_assessment``; it leads the MCP wire so a host that keeps only the head of a
    large structured result still shows it.
    """

    definitions = cast(dict[str, JsonValue], document["$defs"])
    success = cast(dict[str, JsonValue], definitions["success"])
    properties = cast(dict[str, JsonValue], success["properties"])
    properties["agent_next"] = dict(_AGENT_NEXT_TEXT)


def _add_check_reviewer(document: dict[str, JsonValue]) -> None:
    """#1118: the reviewer conversation's record on the check success (check-result 1.6.0)."""

    definitions = cast(dict[str, JsonValue], document["$defs"])
    _add_reviewer_definitions(definitions)
    success = cast(dict[str, JsonValue], definitions["success"])
    cast(dict[str, JsonValue], success["properties"])["reviewer"] = {
        "$ref": "#/$defs/reviewer_record"
    }


def _add_reviewer_definitions(definitions: dict[str, JsonValue]) -> None:
    """#1118: the reviewer conversation's record, shared by check-result and check-recorded.

    Closed tokens, decimal counts, digests, service-issued root aliases and opaque identities:
    never a path, an argument or read text.
    """

    count: dict[str, JsonValue] = {
        "maxLength": 6,
        "pattern": "^(0|[1-9][0-9]{0,5})$",
        "type": "string",
    }
    token: dict[str, JsonValue] = {"pattern": "^[a-z][a-z0-9_]{0,95}$", "type": "string"}

    def nullable(schema: dict[str, JsonValue]) -> dict[str, JsonValue]:
        return {"oneOf": [schema, {"type": "null"}]}

    def enum(*values: str) -> dict[str, JsonValue]:
        return {"enum": list(values), "type": "string"}

    read_properties: dict[str, JsonValue] = {
        "action": enum("read_file", "read_ledger", "read_packet_section"),
        "baseline": nullable(enum("admission_time", "check_time", "read_time", "task_start")),
        "call": enum("1", "2", "3", "4", "5"),
        "disclosure": nullable(
            {"pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", "type": "string"}
        ),
        "lines": nullable({"items": count, "maxItems": 2, "minItems": 2, "type": "array"}),
        "reason": nullable(token),
        "result_bytes": count,
        "result_digest": {"pattern": "^sha256:[0-9a-f]{64}$", "type": "string"},
        "root": nullable({"pattern": "^[a-z][0-9]{1,2}$", "type": "string"}),
        "source": nullable(
            {
                "pattern": "^(?:src_[0-9a-f]{24}|[A-Za-z0-9][A-Za-z0-9._:-]{0,127})$",
                "type": "string",
            }
        ),
        "standing": nullable(
            enum(
                "agent_assertion",
                "declared_test",
                "finishup_record",
                "outside_input_mutable",
                "outside_input_snapshot",
                "task_transcription",
                "workspace_content",
            )
        ),
        "status": enum("denied", "ok", "partial", "stale", "unavailable"),
    }
    reviewer_read: dict[str, JsonValue] = {
        "additionalProperties": False,
        "properties": read_properties,
        "required": cast(list[JsonValue], sorted(read_properties)),
        "type": "object",
    }
    definitions["reviewer_read"] = reviewer_read
    record_properties: dict[str, JsonValue] = {
        "cleanup": nullable(token),
        "ended": nullable(token),
        "exchanges": count,
        "read_bytes": count,
        "reads": {"items": {"$ref": "#/$defs/reviewer_read"}, "maxItems": 5, "type": "array"},
        "reads_used": enum("0", "1", "2", "3"),
    }
    reviewer_record: dict[str, JsonValue] = {
        "additionalProperties": False,
        "properties": record_properties,
        "required": cast(list[JsonValue], sorted(record_properties)),
        "type": "object",
    }
    definitions["reviewer_record"] = reviewer_record


def _add_status_check_outcome(definitions: dict[str, JsonValue]) -> None:
    """A completed check's outcome on its operation page (W6; unreleased 1.4.0, in place).

    The verdict, ``agent_next``, ``overall_next``, the missing items, the AI-powered review outcome
    and the result frontier, in the exact shapes check-result 1.5.0 gives them.
    """

    entry = next(
        item
        for item in _REGISTRY
        if item.relative_path == "operations/check-result-1.6.0.schema.json"
    )
    check_definitions = cast(dict[str, JsonValue], _check_result_v1_6_schema(entry)["$defs"])
    check_success = cast(dict[str, JsonValue], check_definitions["success"])
    check_properties = cast(dict[str, JsonValue], check_success["properties"])
    definitions["check_overall_next"] = copy.deepcopy(check_definitions["overall_next"])
    definitions["check_missing_item"] = copy.deepcopy(check_definitions["missing_item"])
    definitions["status_check_outcome"] = {
        "additionalProperties": False,
        "properties": {
            "agent_next": dict(_AGENT_NEXT_TEXT),
            # #1162 tracked advice (PR #1214 review): the check's advisory identities,
            # structural only, so a recovered outcome keeps what respond answers.
            "correctness_advisories": _outcome_correctness_advisories_schema(),
            "missing_for_assessment": {
                "items": {"$ref": "#/$defs/check_missing_item"},
                "maxItems": 8,
                "type": "array",
                "uniqueItems": True,
            },
            "overall_next": {"$ref": "#/$defs/check_overall_next"},
            "result_frontier": copy.deepcopy(check_properties["result_frontier"]),
            "semantic_conclusion": copy.deepcopy(check_properties["semantic_conclusion"]),
            "semantic_reason": copy.deepcopy(check_properties["semantic_reason"]),
            "semantic_status": copy.deepcopy(check_properties["semantic_status"]),
            "verdict": copy.deepcopy(check_properties["verdict"]),
        },
        "required": ["result_frontier", "semantic_reason", "semantic_status", "verdict"],
        "type": "object",
    }
    page = cast(dict[str, JsonValue], definitions["operation_page"])
    cast(dict[str, JsonValue], page["properties"])["check_outcome"] = {
        "$ref": "#/$defs/status_check_outcome"
    }
    cast(list[JsonValue], page.setdefault("allOf", [])).append(
        {
            "if": {"required": ["check_outcome"]},
            "then": {
                "properties": {
                    "operation_kind": {"const": "check"},
                    "state": {"const": "complete"},
                },
                "required": ["operation_kind", "state"],
            },
        }
    )


# Issue #1048 (ADR-047): the closed vocabularies of a ``mode: inspect`` result.
_INSPECTION_MISSING_KINDS: Final = (
    "blocker_unconfirmed",
    "command_attempt_mismatch",
    "command_run_not_observed",
    "requested_item_not_attempted",
    "resolution_evidence_not_cited",
)
_INSPECTION_LISTED_MATERIAL_CLASSES: Final = (
    "edit_or_write",
    "exploration",
    "non_counting_write",
    "other",
)
_INSPECTION_WRITE_SCOPES: Final = (
    "notes",
    "outside_workspace",
    "scratch",
    "workspace",
    "yoetz_owned",
)
_INSPECTION_ALIGNMENTS: Final = (
    "evidence_names_declared_item",
    "evidence_off_declared_items",
    "evidence_unattributed",
    "no_declared_items",
)
_INSPECTION_ACTION_KINDS: Final = ("command", "edit", "other", "research", "review")
_INSPECTION_OUTCOMES: Final = ("failure", "partial", "success", "unknown")
_INSPECTION_ITEM_INDEX: Final = "^(?:[0-9]|[1-5][0-9]|6[0-3])$"
_INSPECTION_COMMITMENT: Final[Mapping[str, JsonValue]] = MappingProxyType(
    {
        "maxLength": 76,
        "minLength": 76,
        "pattern": "^hmac-sha256:[0-9a-f]{64}$",
        "type": "string",
    }
)


def _add_check_inspection(document: dict[str, JsonValue]) -> None:
    """The read-only ``inspection`` branch of check-result 1.4.0 (issue #1048, ADR-047).

    Additive on the unreleased 1.4.0 contract: a ``mode: inspect`` check records nothing, mints
    no findings and calls no reviewer, so it answers with its own branch (``state: inspected``)
    instead of a completion-grade shape. Every leaf is structural: ids, closed tokens, counts,
    item indexes and keyed command commitments, never command text, paths or prose.
    """

    definitions = cast(dict[str, JsonValue], document["$defs"])

    def ref(name: str) -> dict[str, JsonValue]:
        return {"$ref": f"#/$defs/{name}"}

    def id_pattern(prefixes: str) -> dict[str, JsonValue]:
        return {"pattern": f"^(?:{prefixes})_{_UUID_ID}$", "type": "string"}

    def enum(values: Sequence[str]) -> dict[str, JsonValue]:
        return {"enum": list(values), "type": "string"}

    def array(items: dict[str, JsonValue], limit: int) -> dict[str, JsonValue]:
        return {"items": items, "maxItems": limit, "type": "array"}

    item_indexes: dict[str, JsonValue] = {
        "items": {"pattern": _INSPECTION_ITEM_INDEX, "type": "string"},
        "maxItems": 64,
        "type": "array",
        "uniqueItems": True,
    }
    gap_codes: dict[str, JsonValue] = {
        "items": {
            "maxLength": 145,
            "pattern": r"^(?:unclassified_gap:)?[a-z][a-z0-9_]{0,127}$",
            "type": "string",
        },
        "maxItems": 128,
        "type": "array",
        "uniqueItems": True,
    }
    definitions["inspection_missing"] = {
        "additionalProperties": False,
        "properties": {
            "item_indexes": item_indexes,
            "kind": enum(_INSPECTION_MISSING_KINDS),
            "owner": enum(("agent", "yoetz")),
        },
        "required": ["kind", "owner"],
        "type": "object",
    }
    definitions["inspection_obligation"] = {
        "additionalProperties": False,
        "properties": {
            "closure_basis": enum(_OBLIGATION_CLOSURE_BASES),
            "closure_class": enum(("agent_work", "settled_disclosed", "settled_unmet")),
            "missing": array(ref("inspection_missing"), 8),
            "obligation_id": id_pattern("obl"),
        },
        "required": ["closure_basis", "closure_class", "missing", "obligation_id"],
        "type": "object",
    }
    definitions["inspection_finding"] = {
        "additionalProperties": False,
        "properties": {
            "closure_basis": enum(_FINDING_CLOSURE_BASES),
            "closure_class": enum(
                ("agent_work", "awaiting_ruling", "settled_disclosed", "settled_unmet")
            ),
            "finding_id": ref("finding_id"),
        },
        "required": ["closure_basis", "closure_class", "finding_id"],
        "type": "object",
    }
    definitions["inspection_remaining"] = {
        "additionalProperties": False,
        "properties": {
            "agent_actionable": gap_codes,
            "finding_count": ref("canonical_uint"),
            "findings": array(ref("inspection_finding"), 64),
            "obligation_count": ref("canonical_uint"),
            "obligations": array(ref("inspection_obligation"), 64),
            "predicted_conclusion": enum(_RECEIPT_CONCLUSIONS),
            "readiness": enum(("action_required", "ready", "ready_with_limitations", "unknown")),
            "standing_limitations": gap_codes,
        },
        "required": [
            "agent_actionable",
            "finding_count",
            "findings",
            "obligation_count",
            "obligations",
            "readiness",
            "standing_limitations",
        ],
        "type": "object",
    }
    definitions["inspection_observed_action"] = {
        "additionalProperties": False,
        "properties": {
            "action_kind": enum(_INSPECTION_ACTION_KINDS),
            "command_commitment": dict(_INSPECTION_COMMITMENT),
            "event_id": id_pattern("evt"),
            "exit_status": {"maximum": 2147483647, "minimum": -2147483648, "type": "integer"},
            "ledger_sequence": ref("canonical_uint"),
            "material_class": enum(_INSPECTION_LISTED_MATERIAL_CLASSES),
            "outcome": enum(_INSPECTION_OUTCOMES),
            "tool_name": {
                "maxLength": 128,
                "minLength": 1,
                "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$",
                "type": "string",
            },
            "write_scope": enum(_INSPECTION_WRITE_SCOPES),
        },
        "required": ["action_kind", "event_id", "ledger_sequence", "material_class"],
        "type": "object",
    }
    definitions["inspection_observed"] = {
        "additionalProperties": False,
        "properties": {
            "action_count": ref("canonical_uint"),
            "actions": array(ref("inspection_observed_action"), 64),
            "last_check_frontier": ref("canonical_uint"),
        },
        "required": ["action_count", "actions"],
        "type": "object",
    }
    definitions["inspection_declared_item"] = {
        "additionalProperties": False,
        "properties": {
            "index": {"pattern": _INSPECTION_ITEM_INDEX, "type": "string"},
            "item_kind": enum(("command", "directory", "file")),
        },
        "required": ["index", "item_kind"],
        "type": "object",
    }
    definitions["inspection_evidence_source"] = {
        "additionalProperties": False,
        "properties": {
            "command_commitment": dict(_INSPECTION_COMMITMENT),
            "named_item_indexes": item_indexes,
            "origin": enum(("asserted", "observed", "unattributed")),
            "outcome": enum(_INSPECTION_OUTCOMES),
            "ref": id_pattern("evd|res"),
        },
        "required": ["named_item_indexes", "origin", "ref"],
        "type": "object",
    }
    definitions["inspection_alignment_obligation"] = {
        "additionalProperties": False,
        "properties": {
            "alignment": enum(_INSPECTION_ALIGNMENTS),
            "declared_items": array(ref("inspection_declared_item"), 64),
            "obligation_id": id_pattern("obl"),
            "sources": array(ref("inspection_evidence_source"), 64),
        },
        "required": ["alignment", "declared_items", "obligation_id", "sources"],
        "type": "object",
    }
    definitions["inspection_alignment"] = {
        "additionalProperties": False,
        "properties": {
            "basis": {"const": "recorded_links"},
            "obligation_count": ref("canonical_uint"),
            "obligations": array(ref("inspection_alignment_obligation"), 64),
            "off_declared_count": ref("canonical_uint"),
        },
        "required": ["basis", "obligation_count", "obligations", "off_declared_count"],
        "type": "object",
    }
    definitions["inspection"] = {
        "additionalProperties": False,
        "properties": {
            "evidence_alignment": ref("inspection_alignment"),
            "observations_awaited": ref("observations_awaited"),
            "observed_since_check": ref("inspection_observed"),
            "ok": {"const": True},
            "privacy_projection": {
                "$ref": SCHEMA_NAMESPACE
                + "common/operation-result-1.0.0.schema.json#/$defs/privacy_projection"
            },
            "protocol_version": {"const": "0.1"},
            "remaining": ref("inspection_remaining"),
            "request_id": ref("request_id"),
            "schema_version": {"const": "1.0.0"},
            "session_id": ref("session_id"),
            "state": {"const": "inspected"},
            "subject_frontier": {"$ref": SCHEMA_NAMESPACE + "common/frontier-1.0.0.schema.json"},
            "task_id": ref("task_id"),
            "writer_id": ref("writer_id"),
        },
        "required": [
            "evidence_alignment",
            "observed_since_check",
            "ok",
            "privacy_projection",
            "protocol_version",
            "remaining",
            "request_id",
            "schema_version",
            "session_id",
            "state",
            "subject_frontier",
            "task_id",
            "writer_id",
        ],
        "type": "object",
    }
    branches = cast(list[JsonValue], document["oneOf"])
    branches.insert(2, ref("inspection"))


def _add_check_closure_verdict(definitions: dict[str, JsonValue]) -> None:
    """The one closure verdict on check-result 1.4.0 (tb4n3 RC-3, issue #1026, ADR-046).

    Additive and optional on the unreleased wire: a rejected finding that awaits a reviewer
    ruling has its own continuation (``request_ruling``), the checklist counts the rest of the
    closure classes (emitted only when non-zero), each row names its class and basis, and
    ``overall_next`` carries the receipt conclusion a request now would carry.
    """

    item = cast(dict[str, JsonValue], definitions["checklist_item"])
    cast(dict[str, JsonValue], item["properties"]).update(
        {
            "closure_basis": {"enum": list(_FINDING_CLOSURE_BASES), "type": "string"},
            "closure_class": {"enum": list(_FINDING_CLOSURE_CLASSES), "type": "string"},
        }
    )
    cast(list[JsonValue], item.setdefault("allOf", [])).append(
        {
            "if": {"anyOf": [{"required": ["closure_class"]}, {"required": ["closure_basis"]}]},
            "then": {"required": ["closure_basis", "closure_class"]},
        }
    )
    checklist = cast(dict[str, JsonValue], definitions["finding_checklist"])
    checklist_properties = cast(dict[str, JsonValue], checklist["properties"])
    counts = cast(dict[str, JsonValue], checklist_properties["counts"])
    closure_counter_names = ("awaiting_ruling", "disclosed", "to_disclose", "to_do", "unmet")
    cast(dict[str, JsonValue], counts["properties"]).update(
        {name: {"$ref": "#/$defs/canonical_uint"} for name in closure_counter_names}
    )
    # The five closure counters travel together (an earlier build omits all of them).
    cast(list[JsonValue], counts.setdefault("allOf", [])).append(
        {
            "if": {"anyOf": [{"required": [name]} for name in closure_counter_names]},
            "then": {"required": list(closure_counter_names)},
        }
    )
    # ``disclose_limitations``: the only remaining agent work is a reviewer's limitation request
    # the agent has not answered (owner decision 2026-10-12, #1024).
    cast(dict[str, JsonValue], checklist_properties["next"])["enum"] = [
        "decide_at_budget",
        "disclose_limitations",
        "request_receipt",
        "request_ruling",
        "work_open_findings",
    ]
    overall = cast(dict[str, JsonValue], definitions["overall_next"])
    overall_properties = cast(dict[str, JsonValue], overall["properties"])
    action = cast(dict[str, JsonValue], overall_properties["action"])
    action["enum"] = [
        "supply_missing_input",
        "work_open_findings",
        "disclose_limitations",
        "request_ruling",
        "review_recorded_work",
        "request_receipt",
    ]
    overall_properties["predicted_conclusion"] = {
        "enum": list(_RECEIPT_CONCLUSIONS),
        "type": "string",
    }
    rules = cast(list[JsonValue], overall["allOf"])
    for rule in rules:
        condition = cast(dict[str, JsonValue], rule)["if"]
        action_condition = cast(
            dict[str, JsonValue],
            cast(dict[str, JsonValue], cast(dict[str, JsonValue], condition)["properties"]).get(
                "action", {}
            ),
        )
        if action_condition.get("enum") == ["work_open_findings", "review_recorded_work"]:
            action_condition["enum"] = [
                "disclose_limitations",
                "request_ruling",
                "review_recorded_work",
                "work_open_findings",
            ]


def _add_review_input_manifest_to_check_result(document: dict[str, JsonValue]) -> None:
    """Add input coverage/preflight metadata to the current check-result contract."""

    definitions = cast(dict[str, JsonValue], document["$defs"])
    definitions["specification_preflight"] = {
        "additionalProperties": False,
        "properties": {
            "actionable": {"type": "boolean"},
            "content_bytes": {"maximum": 9007199254740991, "minimum": 0, "type": "integer"},
            "content_digest": {"oneOf": [{"$ref": "#/$defs/digest"}, {"type": "null"}]},
            "gap": {
                "oneOf": [
                    {"enum": ["task_statement_not_authorized", "task_statement_not_supplied"]},
                    {"type": "null"},
                ]
            },
            "required": {"type": "boolean"},
            "revision": {
                "oneOf": [
                    {"maximum": 9007199254740991, "minimum": 0, "type": "integer"},
                    {"type": "null"},
                ]
            },
            "source": {
                "oneOf": [
                    {"enum": ["agent_transcribed", "host_captured_user_prompt", "task_title_only"]},
                    {"type": "null"},
                ]
            },
            "status": {"enum": ["complete", "title_only", "missing", "withheld"], "type": "string"},
        },
        "required": [
            "actionable",
            "content_bytes",
            "content_digest",
            "gap",
            "required",
            "revision",
            "source",
            "status",
        ],
        "type": "object",
    }
    # Reuse the exact definitions emitted for outbound-case by constructing the small schema
    # fragment in place; result and provider packet are independently validated documents.
    definitions.setdefault(
        "opaque_ref",
        {
            "maxLength": 128,
            "minLength": 1,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]*$",
            "type": "string",
        },
    )
    definitions.setdefault(
        "digest",
        {"maxLength": 71, "minLength": 71, "pattern": "^sha256:[0-9a-f]{64}$", "type": "string"},
    )
    definitions.setdefault(
        "item_id_list_64",
        {
            "items": {"$ref": "#/$defs/opaque_ref"},
            "maxItems": 64,
            "minItems": 0,
            "type": "array",
            "uniqueItems": True,
        },
    )
    definitions["review_packet"] = {"properties": {}}
    _add_review_input_manifest_to_outbound_case({"$defs": definitions})
    definitions.pop("review_packet", None)
    success = cast(dict[str, JsonValue], definitions["success"])
    success_properties = cast(dict[str, JsonValue], success["properties"])
    success_properties["review_input_manifest"] = {"$ref": "#/$defs/review_input_manifest"}
    awaiting = cast(dict[str, JsonValue], definitions["awaiting_human"])
    awaiting_properties = cast(dict[str, JsonValue], awaiting["properties"])
    awaiting_properties["state"] = {"enum": ["awaiting_human", "awaiting_input"], "type": "string"}
    awaiting_properties["semantic_status"] = {
        "enum": ["awaiting_human", "awaiting_input"],
        "type": "string",
    }
    awaiting_properties["semantic_reason"] = {
        "enum": ["human_approval_required", "review_input_required"],
        "type": "string",
    }
    awaiting_properties["specification_preflight"] = {"$ref": "#/$defs/specification_preflight"}
    _add_review_input_continuation(definitions)


def _add_review_input_continuation(definitions: dict[str, JsonValue]) -> None:
    """Admit the same-request review-input continuation wherever a CHECK continuation projects.

    CHECK returns it on the awaiting_input branch, and STATUS replays the same continuation on
    the pending operation page; both result contracts must carry the branch or the projection
    of a paused check fails validation.
    """

    continuation = cast(dict[str, JsonValue], definitions["continuation"])
    continuation_one_of = cast(list[JsonValue], continuation["oneOf"])
    continuation_one_of.append(
        {
            "additionalProperties": False,
            "properties": {
                "command": {
                    "items": False,
                    "maxItems": 4,
                    "minItems": 4,
                    "prefixItems": [
                        # Frozen legacy identifier (ADR-048): the released head shape, widened
                        # by ``_admit_current_launcher_heads`` in every unreleased version.
                        {"const": "yoetz"},
                        {"const": "publish-work"},
                        {"const": "--input"},
                        {"const": "PATH"},
                    ],
                    "type": "array",
                },
                "instruction": {"maxLength": 4096, "minLength": 1, "type": "string"},
                "kind": {"const": "review_input_required"},
                "replay_request_id": {"$ref": "#/$defs/request_id"},
            },
            "required": ["kind", "command", "replay_request_id", "instruction"],
            "type": "object",
        }
    )


def _verification_coverage_schema() -> dict[str, JsonValue]:
    """The same bounded advisory member on status and local receipts (#1170)."""

    def text(category: str, limit: int) -> dict[str, JsonValue]:
        return {
            "oneOf": [
                {"type": "string", "minLength": 1, "maxLength": limit},
                {
                    "allOf": [
                        {
                            "$ref": SCHEMA_NAMESPACE
                            + "common/operation-result-1.0.0.schema.json#/$defs/omitted_content"
                        },
                        {"properties": {"category": {"const": category}}, "required": ["category"]},
                    ]
                },
            ]
        }

    count: dict[str, JsonValue] = {"type": "integer", "minimum": 0, "maximum": 2**53 - 1}
    witness: dict[str, JsonValue] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "result_id": {
                "type": "string",
                "pattern": r"^res_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            },
            "action_id": {
                "type": "string",
                "pattern": r"^act_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            },
            "data_source": {
                "enum": [
                    "task_public",
                    "own_generated",
                    "independent",
                    "held_out",
                    "stated_environment",
                    "unknown",
                ]
            },
            "cases": count,
            "failing": count,
            "stale": {"type": "boolean"},
            "freshness": {"type": "string", "enum": ["current", "stale", "unknown", "legacy"]},
            "tuned_on_these_cases": {"type": "boolean"},
            "worst": text("command_metadata", 64),
            "checks": text("command_metadata", 200),
            "expected_from": {"enum": list(VERIFICATION_EXPECTED_FROM)},
        },
        "required": ["result_id", "action_id", "data_source", "cases", "failing", "stale"],
        "allOf": [
            {
                "if": {
                    "properties": {"freshness": {"enum": ["current", "unknown"]}},
                    "required": ["freshness"],
                },
                "then": {"properties": {"stale": {"const": False}}},
            },
            {
                "if": {"properties": {"freshness": {"const": "stale"}}, "required": ["freshness"]},
                "then": {"properties": {"stale": {"const": True}}},
            },
        ],
    }
    criterion: dict[str, JsonValue] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "task_criterion_quote": text("task_description", 240),
            "obligation_criterion_quote": text("obligation_text", 240),
            "source": {"enum": ["task_statement", "obligation", "manifest_quote"]},
            "flags": {
                "type": "array",
                "maxItems": 7,
                "uniqueItems": True,
                "items": {
                    "enum": [
                        "no_test",
                        "failing_cases",
                        "own_or_tuned_only",
                        "public_only",
                        "stale",
                        "repeated_run",
                        "redundant_tests",
                    ]
                },
            },
            "witnesses": {"type": "array", "maxItems": 3, "items": witness},
            "unresolved_failing_runs": count,
            "repeated_runs": count,
            "redundant_tests": count,
            "omitted_witnesses": count,
        },
        "required": [
            "source",
            "flags",
            "witnesses",
            "unresolved_failing_runs",
            "repeated_runs",
            "redundant_tests",
            "omitted_witnesses",
        ],
        "allOf": [
            {
                "if": {"properties": {"source": {"const": "obligation"}}, "required": ["source"]},
                "then": {
                    "required": ["obligation_criterion_quote"],
                    "not": {"required": ["task_criterion_quote"]},
                },
                "else": {
                    "required": ["task_criterion_quote"],
                    "not": {"required": ["obligation_criterion_quote"]},
                },
            }
        ],
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "label": {"const": "agent-declared"},
            "advisory": {"const": True},
            "criteria": {"type": "array", "maxItems": 24, "items": criterion},
            "omitted_criteria": count,
        },
        "required": ["label", "advisory", "criteria", "omitted_criteria"],
    }


def _status_request_v1_2_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Add project, task, and host-correlation selectors to the status request."""

    document = _load_versioned_template(
        entry,
        "operations/status-request-1.1.0.schema.json",
    )
    definitions = cast(dict[str, JsonValue], document["$defs"])
    definitions["project_id"] = {
        "pattern": r"^prj_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        "type": "string",
    }
    definitions["task_id"] = _lineage_id_schema("task_id")
    definitions["host_correlation"] = {
        "maxLength": 256,
        "minLength": 1,
        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:/+\-]*$",
        "type": "string",
    }
    # Issue #914, unreleased in-place addition: the writer-relative evidence selector. A closed
    # one-member enum, so the caller can ask for its own rows but never assert membership.
    evidence_filter = cast(dict[str, JsonValue], definitions["evidence_filter"])
    cast(dict[str, JsonValue], evidence_filter["properties"])["author"] = {"enum": ["mine"]}
    properties = cast(dict[str, JsonValue], document["properties"])
    properties.update(
        {
            "correlation_id": {"$ref": "#/$defs/host_correlation"},
            "project_id": {"$ref": "#/$defs/project_id"},
            "task_id": {"$ref": "#/$defs/task_id"},
        }
    )
    view = cast(dict[str, JsonValue], properties["view"])
    values = cast(list[JsonValue], view["enum"])
    for value in ("lineage", "project", "coverage"):
        if value not in values:
            values.append(value)
    findings_filter = cast(dict[str, JsonValue], definitions["findings_filter"])
    filter_properties = cast(dict[str, JsonValue], findings_filter["properties"])
    _admit_terminal_dispositions(cast(dict[str, JsonValue], filter_properties["disposition"]))
    # Issue #996: select linked duplicates too.
    filter_disposition = cast(dict[str, JsonValue], filter_properties["disposition"])
    filter_values = cast(list[JsonValue], filter_disposition["enum"])
    filter_values.append(_DUPLICATE_OF)
    filter_values.sort(key=lambda item: str(item).encode("ascii"))
    rules = cast(list[JsonValue], document["allOf"])
    # The no-filter branch in v1.1 also contains the previously-added results view.  Keep the
    # selector views explicitly filter-free in this successor.
    rules.append(
        {
            "if": {
                "properties": {"view": {"enum": ["lineage", "project", "coverage"]}},
                "required": ["view"],
            },
            "then": {"not": {"required": ["filter"]}},
        }
    )
    # Selectors are pairwise exclusive.  Separate rules keep each conflict addressable by the
    # protocol validator rather than hiding all three cases in one opaque branch.
    for left, right in (
        ("project_id", "task_id"),
        ("project_id", "correlation_id"),
        ("task_id", "correlation_id"),
    ):
        rules.append({"not": {"required": [left, right]}})
    rules.extend(
        [
            {
                "if": {"required": ["project_id"]},
                "then": {"properties": {"view": {"const": "project"}}},
            },
            {
                "if": {"required": ["correlation_id"]},
                "then": {"properties": {"view": {"const": "lineage"}}},
            },
        ]
    )
    _add_status_request_token_economy(document)
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    document["title"] = f"Yoetz status request {entry.schema_version}"
    return document


def _add_status_request_token_economy(document: dict[str, JsonValue]) -> None:
    """Issue #1084, unreleased in-place additions that cut what a status read costs.

    * ``detail``: ``brief`` returns only what the next step needs (one frontier, the page, the
      closure state); ``full`` (the protocol default when absent) is the earlier body.
    * ``limit`` becomes optional; the service pages 20 items when it is absent.
    * ``view: results`` admits the filters agents already sent it: results after an ingestion
      sequence, results an actor published, and the caller's own results.
    """

    definitions = cast(dict[str, JsonValue], document["$defs"])
    properties = cast(dict[str, JsonValue], document["properties"])
    properties["detail"] = {"enum": ["brief", "full"], "type": "string"}
    document["required"] = [
        name for name in cast(list[JsonValue], document["required"]) if name != "limit"
    ]
    definitions["results_filter"] = {
        "additionalProperties": False,
        "properties": {
            "actor_id": {"$ref": "#/$defs/actor_id"},
            "after_sequence": {"$ref": "#/$defs/canonical_uint"},
            "author": {"enum": ["mine"]},
        },
        "type": "object",
    }
    filter_schema = cast(dict[str, JsonValue], properties["filter"])
    cast(list[JsonValue], filter_schema["anyOf"]).append({"$ref": "#/$defs/results_filter"})
    rules = cast(list[JsonValue], document["allOf"])
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        condition = rule.get("if")
        if not isinstance(condition, dict):
            continue
        view = cast(dict[str, JsonValue], condition.get("properties", {})).get("view")
        if isinstance(view, dict) and isinstance(view.get("enum"), list):
            values = cast(list[JsonValue], view["enum"])
            if "results" in values and "compact" in values:
                values.remove("results")
    rules.append(
        {
            "if": {"properties": {"view": {"const": "results"}}, "required": ["view", "filter"]},
            "then": {"properties": {"filter": {"$ref": "#/$defs/results_filter"}}},
        }
    )


def _status_result_v1_4_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Add lineage and project pages while preserving every earlier status view."""

    document = _load_versioned_template(
        entry,
        "operations/status-result-1.3.0.schema.json",
    )
    definitions = cast(dict[str, JsonValue], document["$defs"])
    # The v1.4 history row exposes the metadata-only provider-bound review manifest.  Build the
    # shared definition in place without changing the frozen v1.0/v1.1 history schemas.
    totals_properties = cast(dict[str, JsonValue], _check_totals_schema()["properties"])
    test_edits = cast(dict[str, JsonValue], totals_properties["test_edits"])
    test_edit_properties = cast(dict[str, JsonValue], test_edits["properties"])
    test_edit_properties["checked_frontier"] = {
        "$ref": SCHEMA_NAMESPACE + "common/frontier-1.0.0.schema.json"
    }
    test_edit_properties["read_availability"] = {
        "enum": ["available", "unavailable", "unknown"],
        "type": "string",
    }
    test_edits["required"] = sorted(test_edit_properties)
    test_edits["allOf"] = [
        {
            "if": {"properties": {"examined": {"const": "0"}}},
            "then": {"properties": {"read_availability": {"const": "unavailable"}}},
            "else": {
                "if": {
                    "anyOf": [
                        {"properties": {"baseline_known": {"const": "0"}}},
                        {"properties": {"unknown": {"not": {"const": "0"}}}},
                    ]
                },
                "then": {"properties": {"read_availability": {"const": "unknown"}}},
                "else": {"properties": {"read_availability": {"const": "available"}}},
            },
        }
    ]
    definitions["latest_check_test_edits"] = test_edits
    compact_item = cast(dict[str, JsonValue], definitions["compact_item"])
    cast(dict[str, JsonValue], compact_item["properties"])["latest_check_test_edits"] = {
        "$ref": "#/$defs/latest_check_test_edits"
    }
    # #1027: which recorded check the latest tested state points at and its closed verdict, so a
    # post-compaction recap can name it. Optional on the compact item, absent when no check exists.
    definitions["latest_check"] = {
        "additionalProperties": False,
        "properties": {
            "check_event_id": {"$ref": "#/$defs/event_id"},
            "checked_frontier": {"$ref": SCHEMA_NAMESPACE + "common/frontier-1.0.0.schema.json"},
            "verdict": {
                "enum": [
                    "action_required",
                    "incomplete_check",
                    "insufficient_coverage",
                    "no_issue_detected",
                ],
                "type": "string",
            },
        },
        "required": ["check_event_id", "checked_frontier", "verdict"],
        "type": "object",
    }
    cast(dict[str, JsonValue], compact_item["properties"])["latest_check"] = {
        "$ref": "#/$defs/latest_check"
    }
    definitions.setdefault(
        "opaque_ref",
        {
            "maxLength": 128,
            "minLength": 1,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]*$",
            "type": "string",
        },
    )
    definitions.setdefault(
        "digest",
        {"maxLength": 71, "minLength": 71, "pattern": "^sha256:[0-9a-f]{64}$", "type": "string"},
    )
    definitions.setdefault(
        "item_id_list_64",
        {
            "items": {"$ref": "#/$defs/opaque_ref"},
            "maxItems": 64,
            "minItems": 0,
            "type": "array",
            "uniqueItems": True,
        },
    )
    definitions["review_packet"] = {"properties": {}}
    _add_review_input_manifest_to_outbound_case({"$defs": definitions})
    _add_test_check_to_review_input_manifest({"$defs": definitions})
    definitions.pop("review_packet", None)
    history_item = cast(dict[str, JsonValue], definitions["history_item"])
    history_properties = cast(dict[str, JsonValue], history_item["properties"])
    history_properties["review_input_manifest"] = {"$ref": "#/$defs/review_input_manifest"}
    history_properties["correctness_advisories"] = _correctness_advisories_schema(history=True)
    history_properties["advisory_subject_frontier"] = {
        "$ref": SCHEMA_NAMESPACE + "common/frontier-1.0.0.schema.json"
    }
    history_properties["advisory_provenance"] = {
        "$ref": SCHEMA_NAMESPACE + "findings/semantic-provenance-1.2.0.schema.json"
    }
    cast(
        dict[str, JsonValue],
        cast(dict[str, JsonValue], definitions["closure_readiness"])["properties"],
    )["correctness_advisory_summary"] = {"type": "string", "minLength": 1, "maxLength": 4096}
    # #1162 tracked advice (unreleased, in place): the receipt's own advisory counts, so a
    # status line counts unanswered advice without parsing prose. Omitted while there is none.
    cast(
        dict[str, JsonValue],
        cast(dict[str, JsonValue], definitions["closure_readiness"])["properties"],
    )["correctness_advisory_counts"] = _advisory_counts_schema()
    cast(
        dict[str, JsonValue],
        cast(dict[str, JsonValue], definitions["closure_readiness"])["properties"],
    )["evidence_basis_summary"] = {"type": "string", "minLength": 1, "maxLength": 4096}
    # Issue #1084 (review R7), unreleased in-place addition: present only when the publish that
    # appended the event omitted occurred_at and the service recorded its own clock.
    history_properties["occurred_at_source"] = {
        "description": (
            "Present only when the publish that appended this event omitted occurred_at, so the "
            "service recorded its own clock; occurred_at is then not a caller assertion."
        ),
        "enum": ["service_clock"],
        "type": "string",
    }
    history_summary = cast(dict[str, JsonValue], history_properties["summary_code"])
    history_codes = cast(list[JsonValue], history_summary["enum"])
    history_codes.extend(
        code
        for code in (
            "child_accepted",
            "child_dependencies_recorded",
            "child_rejected",
            "child_written_off",
            "coordination_context_recorded",
            "coordination_disposition_recorded",
            "coordination_obligation_declared",
            "delegation_cancelled",
            "delegation_declared",
            "work_abandoned",
            "work_cancelled",
            "work_closed",
            "work_written_off",
        )
        if code not in history_codes
    )
    history_codes.sort(key=lambda item: str(item).encode("ascii"))
    finding_kind = cast(dict[str, JsonValue], definitions["finding_kind"])
    finding_kind_values = cast(list[JsonValue], finding_kind["enum"])
    for value in (
        "agent_criterion_unmet",
        "code_defect",
        "coordination_overlap",
        "decision_needed",
        "task_requirement_unmet",
    ):
        if value not in finding_kind_values:
            finding_kind_values.append(value)
    finding_kind_values.sort(key=lambda item: str(item).encode("ascii"))
    finding_item = cast(dict[str, JsonValue], definitions["finding_item"])
    finding_item_properties = cast(dict[str, JsonValue], finding_item["properties"])
    definitions["finding_challenge"] = {
        "additionalProperties": False,
        "properties": {
            "alternative_interpretation": {
                "oneOf": [
                    {"$ref": "#/$defs/content_text"},
                    {"$ref": "#/$defs/finding_omission"},
                ]
            },
            "discrepancy": {
                "oneOf": [
                    {"$ref": "#/$defs/content_text"},
                    {"$ref": "#/$defs/finding_omission"},
                ]
            },
            "requested_next_step": {
                "enum": [
                    "act",
                    "answer_question",
                    "dispute_with_evidence",
                    "provide_evidence",
                    "revise_claim",
                    "state_unresolved_limitation",
                ],
                "type": "string",
            },
            "snippet": {
                "oneOf": [
                    {"$ref": "#/$defs/content_text"},
                    {"$ref": "#/$defs/finding_omission"},
                    {"type": "null"},
                ]
            },
            "uncertainty": {
                "oneOf": [
                    {"$ref": "#/$defs/content_text"},
                    {"$ref": "#/$defs/finding_omission"},
                ]
            },
        },
        "required": [
            "alternative_interpretation",
            "discrepancy",
            "requested_next_step",
            "uncertainty",
        ],
        "type": "object",
    }
    finding_item_properties["challenge"] = {"$ref": "#/$defs/finding_challenge"}
    _admit_terminal_dispositions(cast(dict[str, JsonValue], finding_item_properties["disposition"]))
    # Issue #905 to-do facts on each row, and the budget they read against on the page.
    definitions["todo_state"] = _todo_state_schema()
    finding_item_properties["todo_state"] = {"$ref": "#/$defs/todo_state"}
    finding_item_properties["review_rounds"] = {"$ref": "#/$defs/canonical_uint"}
    findings_page = cast(dict[str, JsonValue], definitions["findings_page"])
    cast(dict[str, JsonValue], findings_page["properties"])["review_delivery"] = {
        "oneOf": [
            {"type": "string", "minLength": 1, "maxLength": 4096},
            {"$ref": "#/$defs/finding_omission"},
        ]
    }
    cast(dict[str, JsonValue], findings_page["properties"])["attempt_budget"] = (
        _attempt_budget_schema()
    )
    # tb4n3 RC-7 (#1030): these answers are the agent's last word until a later qualifying check
    # proves the issue absent, so the row may read ``resolved`` then (reverse edge); ``reopened``
    # takes an ``acknowledged_not_done`` answer back and carries a reason too.
    for terminal in (_ACKNOWLEDGED_NOT_DONE, _SELF_VERIFIED, _REOPENED):
        cast(list[JsonValue], finding_item["allOf"]).append(
            {
                "if": {
                    "properties": {"disposition": {"const": terminal}},
                    "required": ["disposition"],
                },
                "then": {
                    "properties": {
                        "reason": {"not": {"type": "null"}},
                        "waiver_expiry": {"type": "null"},
                        "waiver_scope": {"type": "null"},
                    }
                },
            }
        )
    # Issue #996: a ``duplicate_of`` row carries its earlier finding exactly while the link holds.
    item_disposition = cast(dict[str, JsonValue], finding_item_properties["disposition"])
    item_values = cast(list[JsonValue], item_disposition["enum"])
    item_values.append(_DUPLICATE_OF)
    item_values.sort(key=lambda item: str(item).encode("ascii"))
    finding_item_properties[_DUPLICATE_OF_FIELD] = {"$ref": "#/$defs/finding_id"}
    cast(list[JsonValue], finding_item["allOf"]).extend(
        [
            {
                "if": {
                    "properties": {"disposition": {"const": _DUPLICATE_OF}},
                    "required": ["disposition"],
                },
                "then": {
                    "properties": {
                        "waiver_expiry": {"type": "null"},
                        "waiver_scope": {"type": "null"},
                    }
                },
            },
            {
                "if": {"required": [_DUPLICATE_OF_FIELD]},
                "then": {
                    "properties": {"disposition": {"const": _DUPLICATE_OF}},
                    "required": ["disposition"],
                },
            },
        ]
    )
    for definition_name in ("candidate_finding_item", "finding_item"):
        finding_definition = cast(dict[str, JsonValue], definitions[definition_name])
        finding_properties = cast(dict[str, JsonValue], finding_definition["properties"])
        policy_id = cast(dict[str, JsonValue], finding_properties["policy_id"])
        policy_values = cast(list[JsonValue], policy_id["enum"])
        if "coordination" not in policy_values:
            policy_values.append("coordination")
            policy_values.sort(key=lambda item: str(item).encode("ascii"))
    # Issue #914, unreleased in-place addition: each evidence row's ledger-recorded channel. It is
    # optional so rows produced by earlier 0.3 builds still validate; the service always fills it.
    evidence_properties = cast(
        dict[str, JsonValue], cast(dict[str, JsonValue], definitions["evidence_item"])["properties"]
    )
    evidence_properties["publication_channel"] = json.loads(
        json.dumps(history_properties["publication_channel"])
    )
    frontier_ref = SCHEMA_NAMESPACE + "common/frontier-1.0.0.schema.json"
    definitions["project_id"] = {
        "pattern": r"^prj_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        "type": "string",
    }
    definitions["host_correlation"] = {
        "maxLength": 256,
        "minLength": 1,
        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:/+\-]*$",
        "type": "string",
    }
    definitions["positive_uint"] = {
        "maxLength": 19,
        "minLength": 1,
        "pattern": _LINEAGE_POSITIVE_UINT_PATTERN,
        "type": "string",
    }
    definitions["lineage_child"] = {
        "additionalProperties": False,
        "properties": {
            "acceptance": {"enum": ["accepted", "pending", "rejected"], "type": "string"},
            "blocking_conditions": {
                "items": {"$ref": "#/$defs/code"},
                "maxItems": 64,
                "type": "array",
                "uniqueItems": True,
            },
            "depth": {"$ref": "#/$defs/positive_uint"},
            "origin": {
                "enum": ["host_observed", "parent_minted", "self_registered"],
                "type": "string",
            },
            "parent_task_id": {"$ref": "#/$defs/task_id"},
            "rollup_state": {
                "enum": [
                    "annotation",
                    "blocked",
                    "clean",
                    "incomplete",
                    "open_gap",
                    "unavailable",
                ],
                "type": "string",
            },
            "session_health": {
                "enum": ["active", "contact_lost", "ended"],
                "type": "string",
            },
            # Issue #984 (S2): present only when the accepted child has self-verified findings.
            "self_verified_finding_count": {"$ref": "#/$defs/positive_uint"},
            "task_id": {"$ref": "#/$defs/task_id"},
            "work_state": {
                "enum": ["abandoned", "cancelled", "closed", "open", "written_off"],
                "type": "string",
            },
        },
        "required": [
            "acceptance",
            "blocking_conditions",
            "depth",
            "origin",
            "parent_task_id",
            "rollup_state",
            "session_health",
            "task_id",
            "work_state",
        ],
        "type": "object",
    }
    definitions["lineage_annotation"] = {
        "additionalProperties": False,
        "anyOf": [
            {
                "properties": {"subagent_id": {"$ref": "#/$defs/host_correlation"}},
                "required": ["subagent_id"],
            },
            {
                "properties": {"parent_tool_call_id": {"$ref": "#/$defs/host_correlation"}},
                "required": ["parent_tool_call_id"],
            },
        ],
        "properties": {
            "acceptance": {"const": "pending", "type": "string"},
            "correlation_id": {"$ref": "#/$defs/host_correlation"},
            "origin": {"const": "host_observed", "type": "string"},
            "parent_tool_call_id": {
                "oneOf": [{"$ref": "#/$defs/host_correlation"}, {"type": "null"}]
            },
            "subagent_id": {"oneOf": [{"$ref": "#/$defs/host_correlation"}, {"type": "null"}]},
        },
        "required": ["acceptance", "correlation_id", "origin"],
        "type": "object",
    }
    definitions["lineage_page"] = {
        "additionalProperties": False,
        "properties": {
            "annotations": {
                "items": {"$ref": "#/$defs/lineage_annotation"},
                "maxItems": 100,
                "type": "array",
                "uniqueItems": True,
            },
            "children": {
                "items": {"$ref": "#/$defs/lineage_child"},
                "maxItems": 100,
                "type": "array",
                "uniqueItems": True,
            },
            "next_cursor": {"$ref": "#/$defs/nullable_cursor"},
            "parent_task_id": {"oneOf": [{"$ref": "#/$defs/task_id"}, {"type": "null"}]},
        },
        "required": ["annotations", "children", "next_cursor"],
        "type": "object",
    }
    definitions["project_text_ref"] = {
        "additionalProperties": False,
        "properties": {
            "content_digest": {"$ref": "#/$defs/digest"},
            "envelope_digest": {"oneOf": [{"$ref": "#/$defs/digest"}, {"type": "null"}]},
            "object_id": {"$ref": "#/$defs/object_id"},
            "owner_task_id": {"$ref": "#/$defs/task_id"},
            "plaintext_size": {"maximum": 4194304, "minimum": 0, "type": "integer"},
            "route_generation": {"$ref": "#/$defs/positive_uint"},
        },
        "required": [
            "content_digest",
            "object_id",
            "owner_task_id",
            "plaintext_size",
            "route_generation",
        ],
        "type": "object",
    }
    definitions["project_member"] = {
        "additionalProperties": False,
        "properties": {
            "actor_id": {"oneOf": [{"$ref": "#/$defs/actor_id"}, {"type": "null"}]},
            "parent_task_id": {"oneOf": [{"$ref": "#/$defs/task_id"}, {"type": "null"}]},
            "session_health": {
                "enum": ["active", "contact_lost", "ended"],
                "type": "string",
            },
            "task_id": {"$ref": "#/$defs/task_id"},
            "work_state": {
                "enum": ["abandoned", "cancelled", "closed", "open", "written_off"],
                "type": "string",
            },
        },
        "required": ["actor_id", "session_health", "task_id", "work_state"],
        "type": "object",
    }
    definitions["project_detection"] = {
        "additionalProperties": False,
        "properties": {
            "detection_id": {"$ref": "#/$defs/event_id"},
            "open": {"type": "boolean"},
            "resource_count": {"$ref": "#/$defs/canonical_uint"},
            "resource_paths": {
                "oneOf": [
                    {
                        "items": {
                            "maxLength": 4096,
                            "minLength": 1,
                            "type": "string",
                        },
                        "maxItems": 256,
                        "type": "array",
                        "uniqueItems": True,
                    },
                    {"$ref": "#/$defs/resource_omission"},
                ]
            },
            "task_ids": {
                "items": {"$ref": "#/$defs/task_id"},
                "maxItems": 64,
                "minItems": 2,
                "type": "array",
                "uniqueItems": True,
            },
        },
        "required": ["detection_id", "open", "resource_count", "task_ids"],
        "type": "object",
    }
    definitions["resource_omission"] = {
        "allOf": [
            {
                "$ref": (
                    SCHEMA_NAMESPACE
                    + "common/operation-result-1.0.0.schema.json#/$defs/omitted_content"
                )
            },
            {
                "properties": {"category": {"const": "repository_excerpt"}},
                "required": ["category"],
            },
        ]
    }
    advice_item = cast(dict[str, JsonValue], definitions["advice_item"])
    advice_properties = cast(dict[str, JsonValue], advice_item["properties"])
    advice_properties.update(
        {
            "coordination_counterpart_task_id": {"$ref": "#/$defs/task_id"},
            "coordination_detection_id": {"$ref": "#/$defs/event_id"},
            "coordination_membership_generation": {"$ref": "#/$defs/positive_uint"},
            "coordination_project_id": {"$ref": "#/$defs/project_id"},
            "coordination_resource_paths": {
                "oneOf": [
                    {
                        "items": {
                            "maxLength": 4096,
                            "minLength": 1,
                            "type": "string",
                        },
                        "maxItems": 256,
                        "type": "array",
                        "uniqueItems": True,
                    },
                    {"$ref": "#/$defs/resource_omission"},
                ]
            },
        }
    )
    advice_item["allOf"] = [
        {
            "if": {
                "anyOf": [
                    {"required": ["coordination_counterpart_task_id"]},
                    {"required": ["coordination_detection_id"]},
                    {"required": ["coordination_membership_generation"]},
                    {"required": ["coordination_project_id"]},
                    {"required": ["coordination_resource_paths"]},
                ]
            },
            "then": {
                "required": [
                    "coordination_counterpart_task_id",
                    "coordination_detection_id",
                    "coordination_membership_generation",
                    "coordination_project_id",
                    "coordination_resource_paths",
                ]
            },
        }
    ]
    definitions["project_coverage"] = {
        "additionalProperties": False,
        "properties": {
            "coverage": {"const": "unobservable", "type": "string"},
            "coverage_id": {"$ref": "#/$defs/event_id"},
            "gap_code": {"const": "not_observable", "type": "string"},
            "membership_generation": {"$ref": "#/$defs/positive_uint"},
            "project_id": {"$ref": "#/$defs/project_id"},
            "task_id": {"$ref": "#/$defs/task_id"},
        },
        "required": [
            "coverage",
            "coverage_id",
            "gap_code",
            "membership_generation",
            "project_id",
            "task_id",
        ],
        "type": "object",
    }
    definitions["project_receipt"] = {
        "additionalProperties": False,
        "properties": {
            "conclusion": {
                "enum": [
                    "insufficient_coverage",
                    "no_unresolved_deterministic_findings",
                    "unresolved_findings_remain",
                ],
                "type": "string",
            },
            "frontier": {"$ref": frontier_ref},
            "receipt_id": {
                "pattern": r"^rcp_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
                "type": "string",
            },
            "task_id": {"$ref": "#/$defs/task_id"},
        },
        "required": ["conclusion", "frontier", "receipt_id", "task_id"],
        "type": "object",
    }
    definitions["project_page"] = {
        "additionalProperties": False,
        "properties": {
            "description": {
                "oneOf": [
                    {"$ref": "#/$defs/content_text"},
                    {"$ref": "#/$defs/task_omission"},
                ]
            },
            "description_ref": {"oneOf": [{"$ref": "#/$defs/project_text_ref"}, {"type": "null"}]},
            "coverage": {
                "items": {"$ref": "#/$defs/project_coverage"},
                "maxItems": 100,
                "type": "array",
                "uniqueItems": True,
            },
            "detections": {
                "items": {"$ref": "#/$defs/project_detection"},
                "maxItems": 100,
                "type": "array",
                "uniqueItems": True,
            },
            "grant_state": {
                "enum": ["active", "revoked", None],
            },
            "kind": {"enum": ["general", "repository"], "type": "string"},
            "lineage": {"$ref": "#/$defs/lineage_page"},
            "members": {
                "items": {"$ref": "#/$defs/project_member"},
                "maxItems": 100,
                "type": "array",
                "uniqueItems": True,
            },
            "membership_generation": {"$ref": "#/$defs/positive_uint"},
            "next_cursor": {"$ref": "#/$defs/nullable_cursor"},
            "project_id": {"$ref": "#/$defs/project_id"},
            "receipts": {
                "items": {"$ref": "#/$defs/project_receipt"},
                "maxItems": 100,
                "type": "array",
                "uniqueItems": True,
            },
            "title": {
                "oneOf": [
                    {"$ref": "#/$defs/content_text"},
                    {"$ref": "#/$defs/task_omission"},
                ]
            },
            "title_ref": {"oneOf": [{"$ref": "#/$defs/project_text_ref"}, {"type": "null"}]},
        },
        "required": [
            "detections",
            "grant_state",
            "kind",
            "lineage",
            "members",
            "membership_generation",
            "next_cursor",
            "project_id",
            "receipts",
        ],
        "type": "object",
    }
    success = cast(dict[str, JsonValue], definitions["success"])
    properties = cast(dict[str, JsonValue], success["properties"])
    view = cast(dict[str, JsonValue], properties["view"])
    view_values = cast(list[JsonValue], view["enum"])
    for value in ("lineage", "project"):
        if value not in view_values:
            view_values.append(value)
    page = cast(dict[str, JsonValue], properties["page"])
    page_values = cast(list[JsonValue], page["anyOf"])
    page_values.extend([{"$ref": "#/$defs/lineage_page"}, {"$ref": "#/$defs/project_page"}])
    view_values.append("coverage")
    definitions["coverage_page"] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "verification_coverage": _verification_coverage_schema(),
            "next_cursor": {"type": "null"},
        },
        "required": ["verification_coverage", "next_cursor"],
    }
    page_values.append({"$ref": "#/$defs/coverage_page"})
    rules = cast(list[JsonValue], success.setdefault("allOf", []))
    rules.append(
        {
            "if": {"properties": {"view": {"const": "coverage"}}, "required": ["view"]},
            "then": {"properties": {"page": {"$ref": "#/$defs/coverage_page"}}},
        }
    )
    rules.extend(
        [
            {
                "if": {"properties": {"view": {"const": "lineage"}}, "required": ["view"]},
                "then": {"properties": {"page": {"$ref": "#/$defs/lineage_page"}}},
            },
            {
                "if": {"properties": {"view": {"const": "project"}}, "required": ["view"]},
                "then": {"properties": {"page": {"$ref": "#/$defs/project_page"}}},
            },
        ]
    )
    _add_status_semantic_progress(definitions)
    _add_status_operation_admission(definitions)
    _add_status_observed_run(definitions)
    _add_status_closure_checklist(definitions)
    _add_status_closure_verdict(definitions)
    _add_status_finding_frontier(definitions)
    _add_review_input_continuation(definitions)
    _admit_current_launcher_heads(definitions)
    _add_status_credential_heuristic(definitions)
    _add_status_review_mode(definitions)
    _add_status_task_lifecycle(definitions)
    _add_status_requested_item_role(definitions)
    _add_status_operation_server_filled(definitions)
    _add_status_check_outcome(definitions)
    cast(dict[str, JsonValue], cast(dict[str, JsonValue], definitions["success"])["properties"])[
        "agent_status_line"
    ] = dict(_AGENT_STATUS_LINE)
    _add_status_brief_success(document)
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    _admit_recorded_policy_identities(document)
    document["title"] = f"Yoetz status result {entry.schema_version}"
    return document


def _add_status_operation_server_filled(definitions: dict[str, JsonValue]) -> None:
    """Issue #1084: a publish operation page names the values the service filled, when any."""

    definitions["server_filled"] = _server_filled_schema()
    page = cast(dict[str, JsonValue], definitions["operation_page"])
    cast(dict[str, JsonValue], page["properties"])["server_filled"] = {
        "$ref": "#/$defs/server_filled"
    }


# What a brief status body always carries (issue #1084). Everything else in the full body is either
# a repeat of these (three more frontiers), a default (zero lag, a current projection, no import,
# an enforced credential filter) or closure detail that the compact view carries.
_STATUS_BRIEF_REQUIRED: Final[tuple[str, ...]] = (
    "protocol_version",
    "schema_version",
    "request_id",
    "ok",
    "detail",
    "task_id",
    "session_id",
    "writer_id",
    "view",
    "result_frontier",
    "page",
    "gaps",
    "privacy_projection",
)


def _add_status_brief_success(document: dict[str, JsonValue]) -> None:
    """Issue #1084: the ``brief`` status body, a strict subset of the full success body.

    Frontiers equal to ``result_frontier`` are omitted, as are projection metadata at their
    current/zero defaults, an empty import status and an enforced credential filter. The compact
    view keeps ``closure_readiness`` and ``coverage``; every other view carries only
    ``closure_state`` (the readiness state, its blocking conditions and agent-actionable tokens).
    """

    definitions = cast(dict[str, JsonValue], document["$defs"])
    success = cast(dict[str, JsonValue], definitions["success"])
    brief = cast(dict[str, JsonValue], json.loads(json.dumps(success)))
    properties = cast(dict[str, JsonValue], brief["properties"])
    properties["detail"] = {"const": "brief"}
    properties["closure_state"] = {"$ref": "#/$defs/closure_state"}
    readiness = cast(
        dict[str, JsonValue], cast(dict[str, JsonValue], definitions["closure_readiness"])
    )
    readiness_properties = cast(dict[str, JsonValue], readiness["properties"])
    definitions["closure_state"] = {
        "additionalProperties": False,
        "properties": {
            name: json.loads(json.dumps(readiness_properties[name]))
            for name in ("agent_actionable", "blocking_conditions", "fix_or_decline", "state")
            if name in readiness_properties
        },
        "required": ["blocking_conditions"],
        "type": "object",
    }
    brief["required"] = list(_STATUS_BRIEF_REQUIRED)
    rules = cast(list[JsonValue], brief.setdefault("allOf", []))
    rules.append(
        {
            "if": {"properties": {"view": {"const": "compact"}}, "required": ["view"]},
            "then": {
                "not": {"required": ["closure_state"]},
                "required": ["closure_readiness", "coverage"],
            },
            "else": {
                "not": {"anyOf": [{"required": ["closure_readiness"]}, {"required": ["coverage"]}]},
                "required": ["closure_state"],
            },
        }
    )
    definitions["brief_success"] = brief
    branches = cast(list[JsonValue], document["oneOf"])
    branches.insert(1, {"$ref": "#/$defs/brief_success"})


def _credential_heuristic_pair_schema() -> dict[str, JsonValue]:
    state: dict[str, JsonValue] = {"enum": ["disabled", "enforced", "unknown"], "type": "string"}
    return {
        "additionalProperties": False,
        "properties": {"machine_default": dict(state), "repository": dict(state)},
        "required": ["machine_default", "repository"],
        "type": "object",
    }


def _add_setup_credential_heuristic(definitions: dict[str, JsonValue]) -> None:
    """Carry the derived possible-credential filter pair on the repository setup read (#982).

    Optional on the unreleased 2.9.0 control result, so every CLI surface shows the same
    ``repository``/``machine_default`` pair as the status result.
    """

    body = cast(dict[str, JsonValue], definitions["privacy_get_setup_body"])
    for branch in cast(list[JsonValue], body["oneOf"]):
        properties = cast(dict[str, JsonValue], cast(dict[str, JsonValue], branch)["properties"])
        if "grant_state" in properties:
            properties["credential_heuristic"] = _credential_heuristic_pair_schema()


def _add_status_review_mode(definitions: dict[str, JsonValue]) -> None:
    """ADR-049: this conversation's review mode, the owner's setting and the latest switch.

    Optional and additive, closed tokens and ids only. ``mode`` is what the next check runs in;
    ``requested`` is the conversation's default or latest switch; ``local_reason`` says why a
    conversation is local. ``setting_explicit`` is whether the owner chose ``setting`` (a policy
    that predates it has the released reading). ``switch_event_id`` and ``switch_sequence`` name
    the latest switch.
    """

    definitions["status_review_mode"] = {
        "additionalProperties": False,
        "properties": {
            "ai_review_available": {"type": "boolean"},
            "local_reason": {
                "enum": [
                    "ai_review_not_set_up",
                    "conversation_default",
                    "owner_local_only",
                    "review_disabled",
                    "route_local_only",
                    "switched_to_local",
                ],
                "type": "string",
            },
            "mode": {"enum": ["ai_powered", "local"], "type": "string"},
            "requested": {"enum": ["ai_powered", "local"], "type": "string"},
            "setting": {
                "enum": ["ai_powered", "local_agent_opt_in", "local_only", "local_owner_approval"],
                "type": "string",
            },
            "setting_explicit": {"type": "boolean"},
            "switch_event_id": {
                "pattern": (
                    "^evt_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
                ),
                "type": "string",
            },
            "switch_sequence": {"pattern": "^(0|[1-9][0-9]{0,15})$", "type": "string"},
        },
        "required": ["ai_review_available", "mode", "requested", "setting", "setting_explicit"],
        "type": "object",
    }
    success = cast(dict[str, JsonValue], definitions["success"])
    cast(dict[str, JsonValue], success["properties"])["review_mode"] = {
        "$ref": "#/$defs/status_review_mode"
    }


def _add_status_task_lifecycle(definitions: dict[str, JsonValue]) -> None:
    """#1239: the task's own work lifecycle and session health, so a top-level task sees it.

    Optional and additive, closed tokens and times only. ``abandonment_at`` is when the service
    will abandon open work unless contact returns, or when abandoned work was abandoned;
    ``abandonment_reversed`` marks a ``contact_lost`` abandonment the same session closed.
    """

    definitions["status_task_lifecycle"] = {
        "additionalProperties": False,
        "properties": {
            "abandonment_at": {"$ref": "#/$defs/timestamp"},
            "abandonment_reason": {
                "enum": ["attach_handle_expired", "contact_lost", "session_ended"],
                "type": "string",
            },
            "abandonment_reversed": {"const": True},
            "contact_lost_at": {"$ref": "#/$defs/timestamp"},
            "session_health": {"enum": ["active", "contact_lost", "ended"], "type": "string"},
            "work_state": {
                "enum": ["abandoned", "cancelled", "closed", "open", "written_off"],
                "type": "string",
            },
        },
        "required": ["session_health", "work_state"],
        "type": "object",
    }
    success = cast(dict[str, JsonValue], definitions["success"])
    cast(dict[str, JsonValue], success["properties"])["task_lifecycle"] = {
        "$ref": "#/$defs/status_task_lifecycle"
    }


def _add_status_credential_heuristic(definitions: dict[str, JsonValue]) -> None:
    """Name the effective possible-credential filter state before any check runs (issue #982).

    Optional and additive: ``repository`` is what the current repository's grant applies to the
    external AI reviewer, ``machine_default`` what a repository without a grant inherits.
    ``unknown`` when the service could not read the policy.
    """

    definitions["credential_heuristic_state"] = {
        "enum": ["disabled", "enforced", "unknown"],
        "type": "string",
    }
    success = cast(dict[str, JsonValue], definitions["success"])
    cast(dict[str, JsonValue], success["properties"])["credential_heuristic"] = {
        "additionalProperties": False,
        "properties": {
            "machine_default": {"$ref": "#/$defs/credential_heuristic_state"},
            "repository": {"$ref": "#/$defs/credential_heuristic_state"},
        },
        "required": ["machine_default", "repository"],
        "type": "object",
    }


def _add_status_requested_item_role(definitions: dict[str, JsonValue]) -> None:
    """Show obligation_published 1.1.0 ``directory`` items and their optional ``role`` (#1002).

    Unreleased in-place addition to status-result 1.4.0. Earlier status results are frozen and
    never carry either.
    """

    item = cast(dict[str, JsonValue], definitions["status_requested_item"])
    properties = cast(dict[str, JsonValue], item["properties"])
    kinds = cast(list[JsonValue], cast(dict[str, JsonValue], properties["item_kind"])["enum"])
    if "directory" not in kinds:
        kinds.append("directory")
    properties["role"] = {"enum": ["input", "output"], "type": "string"}
    # The row shows an acknowledged_not_done obligation's status and the agent's own reason,
    # under the same obligation-text omission as the description it explains.
    obligation = cast(dict[str, JsonValue], definitions["obligation_item"])
    obligation_properties = cast(dict[str, JsonValue], obligation["properties"])
    status = cast(dict[str, JsonValue], obligation_properties["status"])
    statuses = cast(list[JsonValue], status["enum"])
    if "acknowledged_not_done" not in statuses:
        statuses.append("acknowledged_not_done")
    obligation_properties["acknowledged_not_done_reason"] = {
        "oneOf": [{"$ref": "#/$defs/content_text"}, {"$ref": "#/$defs/obligation_omission"}]
    }
    # #1027: whether the obligation is in the current plan's effective scope (not waived or
    # superseded); optional, absent when the plan scope cannot be read.
    obligation_properties["in_current_plan"] = {"type": "boolean"}


def _fix_or_decline_array(
    obligation: JsonValue | None = None,
) -> dict[str, JsonValue]:
    """Issue #1209: the open fix-or-decline items (a closed code and an obligation id)."""

    return {
        "items": {
            "additionalProperties": False,
            "properties": {
                "code": {
                    "enum": [
                        "planned_verification_agent_linked",
                        "planned_verification_outcome_unknown",
                        "requested_output_unchanged",
                    ],
                    "type": "string",
                },
                "obligation_id": (
                    {"$ref": "#/$defs/obligation_id"} if obligation is None else obligation
                ),
            },
            "required": ["code", "obligation_id"],
            "type": "object",
        },
        "maxItems": 64,
        "type": "array",
    }


def _add_status_closure_checklist(definitions: dict[str, JsonValue]) -> None:
    """Split closure readiness into a checklist with a stop state (issue #913, ADR-032)."""

    readiness = cast(dict[str, JsonValue], definitions["closure_readiness"])
    properties = cast(dict[str, JsonValue], readiness["properties"])
    # ADR-045: where each derived fact the checklist lists came from. Optional and independent.
    definitions["fact_lineage"] = _fact_lineage_definition()
    properties["fact_lineage"] = _fact_lineage_array()
    # tb4n4 (#1044): the delivered files that name files the change created and no item declares,
    # with those root-relative files (repository-excerpt content, each one withheld as the
    # repository omission marker under a privacy policy). Optional, added in place on 1.4.0.
    properties["undeclared_references"] = {
        "items": {
            "additionalProperties": False,
            "properties": {
                "item_index": {
                    "pattern": "^(?:[0-9]|[1-5][0-9]|6[0-3])$",
                    "type": "string",
                },
                "obligation_id": {"$ref": "#/$defs/obligation_id"},
                "paths": {
                    "items": {
                        "oneOf": [
                            {
                                "maxLength": 256,
                                "minLength": 1,
                                "pattern": (
                                    "^[^\\u0000-\\u001f\\u007f/][^\\u0000-\\u001f\\u007f]*$"
                                ),
                                "type": "string",
                            },
                            {"$ref": "#/$defs/resource_omission"},
                        ]
                    },
                    "maxItems": 8,
                    "type": "array",
                },
                "total": {"$ref": "#/$defs/positive_uint"},
            },
            "required": ["item_index", "obligation_id", "paths", "total"],
            "type": "object",
        },
        "maxItems": 16,
        "type": "array",
    }
    properties.update(
        {
            "acknowledged_not_done": {
                "items": {
                    "oneOf": [
                        {"$ref": "#/$defs/finding_id"},
                        {"$ref": "#/$defs/obligation_id"},
                    ]
                },
                "maxItems": 64,
                "type": "array",
                "uniqueItems": True,
            },
            "acknowledged_not_done_count": {"$ref": "#/$defs/canonical_uint"},
            # #997: obligations acknowledged as not done, never in open_obligation_count.
            "acknowledged_obligation_count": {"$ref": "#/$defs/canonical_uint"},
            "agent_actionable": {
                "items": {
                    "maxLength": 145,
                    "pattern": r"^(?:unclassified_gap:)?[a-z][a-z0-9_]{0,127}$",
                    "type": "string",
                },
                "maxItems": 128,
                "type": "array",
                "uniqueItems": True,
            },
            # "3" is the current table (#984 ``finding_self_verified``); "1" and "2" stay admitted
            # for a result an earlier 0.3 build shaped.
            # "5" adds ``finding_disputed_after_rebuttal`` (#1020); "6" adds
            # ``declared_output_emptied`` and ``deliverable_references_undeclared_file`` (#1022);
            # "7" is the table derived from ``kernel.gap_effect`` (#1026), with the
            # ``finding_rejection_awaiting_ruling`` readiness token, and adds
            # ``planned_verification_matched_by_prefix`` and ``declared_output_not_reviewable``
            # (tb4n3 RC-5, ADR-045); "8" makes ``deliverable_references_undeclared_file``
            # agent-actionable (#1044); "9" adds the ``fix_or_decline`` readiness group (#1209).
            "gap_classification_version": {
                "enum": ["1", "2", "3", "4", "5", "6", "7", "8", "9"],
                "type": "string",
            },
            # Issue #1209 (ADR-032 amendment): the open limitations an agent action removes, by
            # closed code and obligation id, sorted. Each code is also a standing limitation.
            # Optional on the unreleased 1.4.0 wire; omitted when none. Never a Stop item.
            "fix_or_decline": _fix_or_decline_array(),
            "standing_limitations": {
                "items": {"$ref": "#/$defs/code"},
                "maxItems": 128,
                "type": "array",
                "uniqueItems": True,
            },
            "state": {
                "enum": ["action_required", "ready", "ready_with_limitations", "unknown"],
                "type": "string",
            },
            # tb4n3 RC-6 (issue #1029): the record that decided check_not_applicable or the
            # bounding check_current_as_of_earlier_frontier. Service-minted ids, a ledger
            # sequence, closed tokens and the recorded tool name; never a path or command text.
            "check_cause": {
                "additionalProperties": False,
                "properties": {
                    "check_event_id": {"$ref": "#/$defs/event_id"},
                    "check_subject_frontier": {"$ref": "#/$defs/canonical_uint"},
                    "effect": {"enum": ["superseded", "bounds_conclusion"], "type": "string"},
                    "event_id": {"$ref": "#/$defs/event_id"},
                    "family": {"$ref": "#/$defs/code"},
                    "ledger_sequence": {"$ref": "#/$defs/canonical_uint"},
                    "material_class": {
                        "enum": [
                            "yoetz_own_call",
                            "response",
                            "exploration",
                            "no_tool_activity",
                            "non_counting_write",
                            "edit_or_write",
                            "other",
                        ],
                        "type": "string",
                    },
                    "rule": {"$ref": "#/$defs/code"},
                    "tool": {
                        "maxLength": 128,
                        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$",
                        "type": "string",
                    },
                },
                "required": [
                    "check_event_id",
                    "check_subject_frontier",
                    "effect",
                    "event_id",
                    "family",
                    "ledger_sequence",
                    "material_class",
                    "rule",
                ],
                "type": "object",
            },
            # Open obligations a recorded yoetz-blocker decision names (#977): ids and the closed
            # kind only. Optional and independent of the checklist group.
            "blocked_obligations": {
                "items": {
                    "additionalProperties": False,
                    "properties": {
                        "blocker_kind": {
                            "enum": [
                                "authority",
                                "consent",
                                "credential",
                                "dependency_unavailable",
                            ],
                            "type": "string",
                        },
                        # #985: claimed until a later decision repeats the same blocker line.
                        # Optional: an earlier 0.3 build omits both.
                        "confirmation": {"enum": ["claimed", "confirmed"], "type": "string"},
                        "confirmation_event_id": {"$ref": "#/$defs/event_id"},
                        "decision_event_id": {"$ref": "#/$defs/event_id"},
                        "obligation_id": {"$ref": "#/$defs/obligation_id"},
                    },
                    "required": ["blocker_kind", "decision_event_id", "obligation_id"],
                    "allOf": [
                        {
                            "if": {
                                "properties": {"confirmation": {"const": "confirmed"}},
                                "required": ["confirmation"],
                            },
                            "then": {"required": ["confirmation_event_id"]},
                            "else": {"not": {"required": ["confirmation_event_id"]}},
                        }
                    ],
                    "type": "object",
                },
                "maxItems": 64,
                "type": "array",
            },
            # #1079: recorded evd_ or res_ ids linked to a flagged obligation. Ids only.
            # Optional on the unreleased 1.4.0 wire; omitted when none. Absence never means a
            # cited id is linked.
            "admissible_verification": {
                "items": {
                    "additionalProperties": False,
                    "properties": {
                        "obligation_id": {"$ref": "#/$defs/obligation_id"},
                        "refs": {
                            "items": {
                                "oneOf": [
                                    {"$ref": "#/$defs/evidence_id"},
                                    {"$ref": "#/$defs/result_id"},
                                ]
                            },
                            "maxItems": 8,
                            "minItems": 1,
                            "type": "array",
                            "uniqueItems": True,
                        },
                    },
                    "required": ["obligation_id", "refs"],
                    "type": "object",
                },
                "maxItems": 8,
                "type": "array",
            },
            # Newest material closing-review input's ingestion sequence, or "0" when none
            # exists. Optional on the unreleased 1.4.0 wire; omitted by an earlier build.
            # "0" is computed and distinct from omission.
            "closing_material_frontier": {"$ref": "#/$defs/canonical_uint"},
            # W5/D1 (ADR-033): resolved obligations whose acceptance provenance FinishUP could
            # not establish (the receipt's coverage limit). Ids and closed reason tokens only.
            # Optional on the unreleased 1.4.0 wire; omitted when none. Never a Stop item.
            "acceptance_risk": {
                "items": {
                    "additionalProperties": False,
                    "properties": {
                        "obligation_id": {"$ref": "#/$defs/obligation_id"},
                        "reasons": {
                            "items": {
                                "enum": [
                                    "requested_item_never_attempted",
                                    "evidence_not_linked_to_declared_items",
                                    "evidence_self_asserted_only",
                                ],
                                "type": "string",
                            },
                            "maxItems": 3,
                            "minItems": 1,
                            "type": "array",
                            "uniqueItems": True,
                        },
                    },
                    "required": ["obligation_id", "reasons"],
                    "type": "object",
                },
                "maxItems": 64,
                "type": "array",
            },
            # F3: the result ids a whole-task completion claim recorded now must name in
            # `limitation_refs` (the reducer's own rule), sorted and bounded, plus the full count.
            # Ids only. Optional on the unreleased 1.4.0 wire; present together.
            "limitation_refs_required": {
                "items": {"$ref": "#/$defs/result_id"},
                "maxItems": 64,
                "type": "array",
                "uniqueItems": True,
            },
            "limitation_refs_required_count": {"$ref": "#/$defs/canonical_uint"},
        }
    )
    # Optional on this unreleased version so a result shaped by an earlier 0.3 build still
    # validates; when present the checklist is complete.
    checklist: list[JsonValue] = [
        "acknowledged_not_done",
        "acknowledged_not_done_count",
        "agent_actionable",
        "gap_classification_version",
        "standing_limitations",
        "state",
    ]
    rules = cast(list[JsonValue], readiness.setdefault("allOf", []))
    rules.extend(
        [
            {
                "if": {"anyOf": [{"required": [name]} for name in checklist]},
                "then": {"required": checklist},
            },
            {
                "if": {
                    "anyOf": [
                        {"required": ["limitation_refs_required"]},
                        {"required": ["limitation_refs_required_count"]},
                    ]
                },
                "then": {
                    "required": ["limitation_refs_required", "limitation_refs_required_count"]
                },
            },
            {
                "if": {
                    "properties": {"state": {"const": "action_required"}},
                    "required": ["state"],
                },
                "then": {"properties": {"agent_actionable": {"minItems": 1}}},
            },
            {
                "if": {
                    "properties": {"state": {"enum": ["ready", "ready_with_limitations"]}},
                    "required": ["state"],
                },
                "then": {"properties": {"agent_actionable": {"maxItems": 0}}},
            },
            {
                "if": {"properties": {"state": {"const": "unknown"}}, "required": ["state"]},
                "then": {
                    "properties": {
                        "acknowledged_not_done": {"maxItems": 0},
                        "agent_actionable": {"const": ["readiness_unknown"]},
                        "blocking_conditions": {"const": ["readiness_unknown"]},
                        "standing_limitations": {"maxItems": 0},
                    }
                },
            },
        ]
    )


_FINDING_CLOSURE_CLASSES: Final = (
    "agent_work",
    "awaiting_ruling",
    "settled_disclosed",
    "settled_unmet",
    "resolved",
)
_OBLIGATION_CLOSURE_CLASSES: Final = (
    "agent_work",
    "resolved",
    "settled_disclosed",
    "settled_unmet",
)
_FINDING_CLOSURE_BASES: Final = (
    "absence_proved",
    "absence_proved_after_acknowledged_not_done",
    "absence_proved_after_self_verified",
    "acknowledged_not_done_bookkeeping",
    "acknowledged_not_done_requirement",
    "disputed_after_rebuttal",
    "failed_run_disclosed",
    "limitation_acknowledged_not_done",
    "limitation_disclosed",
    "limitation_requested",
    "open_answered",
    "open_unanswered",
    "rejected_awaiting_ruling",
    "rejected_review_unavailable",
    "rejection_accepted",
    "reopened",
    "retired_by_passing_run",
    "retired_by_planned_verification",
    "self_verified",
)
_OBLIGATION_CLOSURE_BASES: Final = (
    "acknowledged_not_done",
    "blocker_claimed",
    "blocker_confirmed",
    "externally_evaluated",
    "open",
    "resolved",
    "resolved_deliverable_emptied",
)
_FINDING_NEXT_ACTIONS: Final = (
    "acknowledge",
    "acknowledge_not_done",
    "none",
    "recheck",
    "reject",
    "reopen",
    "repair",
    "self_verify",
)
_PREDICTION_REASON_CODES: Final = (
    "check_suppressed_findings",
    "check_verdict_insufficient",
    "child_findings_actionable",
    "completion_scope_gap",
    "findings_awaiting_ruling",
    "findings_disclosed",
    "findings_to_do",
    "findings_unmet",
    "limitations_to_disclose",
    "lineage_blocks",
    "live_gap_bounds",
    "no_applicable_check",
    "obligations_acknowledged",
    "obligations_disclosed",
    "obligations_open",
    "policy_execution_incomplete",
)
_RECEIPT_CONCLUSIONS: Final = (
    "insufficient_coverage",
    "no_unresolved_deterministic_findings",
    "unresolved_findings_remain",
)
_UUID_ID: Final = "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"


def _predicted_receipt_schema() -> dict[str, JsonValue]:
    """The receipt conclusion a request now would carry, and every rule behind it (ADR-046)."""

    reason: dict[str, JsonValue] = {
        "additionalProperties": False,
        "properties": {
            "code": {"enum": list(_PREDICTION_REASON_CODES), "type": "string"},
            "count": {"$ref": "#/$defs/positive_uint"},
            "refs": {
                "items": {
                    "maxLength": 128,
                    "pattern": f"^(?:(?:fnd|obl)_{_UUID_ID}|[a-z][a-z0-9_]{{0,127}})$",
                    "type": "string",
                },
                "maxItems": 3,
                "type": "array",
                "uniqueItems": True,
            },
            "rule": {
                "enum": ["R1", "R10", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9"],
                "type": "string",
            },
            "since_frontier": {"$ref": "#/$defs/canonical_uint"},
        },
        "required": ["code", "count", "refs", "rule"],
        "type": "object",
    }
    return {
        "additionalProperties": False,
        "properties": {
            "basis_frontier": {"$ref": "#/$defs/canonical_uint"},
            "conclusion": {"enum": list(_RECEIPT_CONCLUSIONS), "type": "string"},
            "provisional": {"type": "boolean"},
            "reason_total": {"$ref": "#/$defs/canonical_uint"},
            "reasons": {"items": reason, "maxItems": 8, "type": "array"},
        },
        "required": ["basis_frontier", "conclusion", "provisional", "reason_total", "reasons"],
        "type": "object",
    }


def _draft_receipt_schema() -> dict[str, JsonValue]:
    """Issue #975 (ADR-046 amendment): what the receipt will say, as a draft (records only)."""

    from finishup.domain.correctness_advisories import ADVISORY_ID_PATTERN

    def excerpt(category: str) -> dict[str, JsonValue]:
        return {
            "oneOf": [
                {"type": "string", "minLength": 1, "maxLength": 160},
                {
                    "allOf": [
                        {
                            "$ref": SCHEMA_NAMESPACE
                            + "common/operation-result-1.0.0.schema.json#/$defs/omitted_content"
                        },
                        {"properties": {"category": {"const": category}}, "required": ["category"]},
                    ]
                },
            ]
        }

    criterion: dict[str, JsonValue] = {
        "additionalProperties": False,
        "allOf": [
            {
                "if": {"properties": {"source": {"const": "obligation"}}, "required": ["source"]},
                "then": {
                    "required": ["obligation_criterion_excerpt"],
                    "not": {"required": ["task_criterion_excerpt"]},
                },
                "else": {
                    "required": ["task_criterion_excerpt"],
                    "not": {"required": ["obligation_criterion_excerpt"]},
                },
            }
        ],
        "properties": {
            "obligation_criterion_excerpt": excerpt("obligation_text"),
            "refs": {
                "items": {"$ref": "#/$defs/subject_id"},
                "maxItems": 3,
                "type": "array",
                "uniqueItems": True,
            },
            "source": {
                "enum": ["task_statement", "obligation", "manifest_quote"],
                "type": "string",
            },
            "standing": {
                "enum": ["linked_pass_current", "agent_claim_only", "none"],
                "type": "string",
            },
            "task_criterion_excerpt": excerpt("task_description"),
        },
        "required": ["refs", "source", "standing"],
        "type": "object",
    }
    return {
        "additionalProperties": False,
        "properties": {
            "advice_unanswered": {
                "items": {"pattern": ADVISORY_ID_PATTERN, "type": "string"},
                "maxItems": 4,
                "type": "array",
                "uniqueItems": True,
            },
            "advice_unanswered_count": {"$ref": "#/$defs/canonical_uint"},
            "conclusion": {"enum": list(_RECEIPT_CONCLUSIONS), "type": "string"},
            "criteria": {"items": criterion, "maxItems": 6, "type": "array"},
            "criteria_counts": {
                "additionalProperties": False,
                "properties": {
                    name: {"$ref": "#/$defs/canonical_uint"}
                    for name in ("agent_claim_only", "linked_pass_current", "none")
                },
                "required": ["agent_claim_only", "linked_pass_current", "none"],
                "type": "object",
            },
            "criteria_total": {"$ref": "#/$defs/canonical_uint"},
            "fix_or_decline_count": {"$ref": "#/$defs/canonical_uint"},
            "label": {"const": "draft_records_not_correctness"},
            "limitation_count": {"$ref": "#/$defs/canonical_uint"},
            "limitations": {
                "items": {"$ref": "#/$defs/code"},
                "maxItems": 8,
                "type": "array",
                "uniqueItems": True,
            },
            "reasons": {
                "items": {"enum": list(_PREDICTION_REASON_CODES), "type": "string"},
                "maxItems": 8,
                "type": "array",
                "uniqueItems": True,
            },
        },
        "required": [
            "advice_unanswered",
            "advice_unanswered_count",
            "conclusion",
            "criteria",
            "criteria_counts",
            "criteria_total",
            "fix_or_decline_count",
            "label",
            "limitation_count",
            "limitations",
            "reasons",
        ],
        "type": "object",
    }


def _add_status_closure_verdict(definitions: dict[str, JsonValue]) -> None:
    """The one closure verdict on status-result 1.4.0 (tb4n3 RC-3, issue #1026, ADR-046).

    Additive and optional, changed in place on the unreleased wire (ADR-040 precedent): the
    predicted receipt conclusion, the finding and obligation counters, the once-per-frontier
    re-reads, and each finding / obligation row's closure class, basis and next actions.
    ``receipt_blocking_finding_count`` keeps its wire meaning (findings to do plus unmet).
    """

    readiness = cast(dict[str, JsonValue], definitions["closure_readiness"])
    properties = cast(dict[str, JsonValue], readiness["properties"])
    properties.update(
        {
            "finding_counts": {
                "additionalProperties": False,
                "properties": {
                    name: {"$ref": "#/$defs/canonical_uint"}
                    for name in (
                        "awaiting_ruling",
                        "disclosed",
                        "self_verify_eligible",
                        "to_disclose",
                        "to_do",
                        "unmet",
                    )
                },
                "required": [
                    "awaiting_ruling",
                    "disclosed",
                    "self_verify_eligible",
                    "to_disclose",
                    "to_do",
                    "unmet",
                ],
                "type": "object",
            },
            "obligation_counts": {
                "additionalProperties": False,
                "properties": {
                    name: {"$ref": "#/$defs/canonical_uint"}
                    for name in ("acknowledged", "disclosed", "open")
                },
                "required": ["acknowledged", "disclosed", "open"],
                "type": "object",
            },
            "predicted_receipt": _predicted_receipt_schema(),
            # Issue #975 (ADR-046 amendment), optional, in place on the unreleased wire: the draft
            # receipt on a ready readiness (the prediction's own conclusion and reasons).
            "draft_receipt": _draft_receipt_schema(),
            "rechecks": {
                "items": {
                    "additionalProperties": False,
                    "properties": {
                        "key": {
                            "maxLength": 160,
                            "pattern": r"^(?:accept|ack|blocker|premise):[A-Za-z0-9_.:?-]{1,140}$",
                            "type": "string",
                        },
                        "kind": {
                            "enum": ["acceptance", "acknowledgement", "blocker", "premise"],
                            "type": "string",
                        },
                        "rule": {"$ref": "#/$defs/code"},
                        "since_frontier": {"$ref": "#/$defs/canonical_uint"},
                        "subjects": {
                            "items": {"$ref": "#/$defs/subject_id"},
                            "maxItems": 8,
                            "type": "array",
                            "uniqueItems": True,
                        },
                    },
                    "required": ["key", "kind", "rule", "since_frontier", "subjects"],
                    "type": "object",
                },
                "maxItems": 128,
                "type": "array",
            },
            "awaiting_ruling_findings": {
                "items": {
                    "additionalProperties": False,
                    "properties": {
                        "finding_id": {"$ref": "#/$defs/finding_id"},
                        "since_frontier": {"$ref": "#/$defs/canonical_uint"},
                    },
                    "required": ["finding_id", "since_frontier"],
                    "type": "object",
                },
                "maxItems": 8,
                "type": "array",
                "uniqueItems": True,
            },
        }
    )
    finding_item = cast(dict[str, JsonValue], definitions["finding_item"])
    cast(dict[str, JsonValue], finding_item["properties"]).update(
        {
            "closure_basis": {"enum": list(_FINDING_CLOSURE_BASES), "type": "string"},
            "closure_class": {"enum": list(_FINDING_CLOSURE_CLASSES), "type": "string"},
            "next_actions": {
                "items": {"enum": list(_FINDING_NEXT_ACTIONS), "type": "string"},
                "maxItems": 8,
                "type": "array",
                "uniqueItems": True,
            },
        }
    )
    cast(list[JsonValue], finding_item.setdefault("allOf", [])).extend(
        [
            {
                "if": {"anyOf": [{"required": ["closure_class"]}, {"required": ["closure_basis"]}]},
                "then": {"required": ["closure_basis", "closure_class"]},
            },
            {
                "if": {"required": ["next_actions"]},
                "then": {"required": ["closure_class"]},
            },
        ]
    )
    obligation_item = cast(dict[str, JsonValue], definitions["obligation_item"])
    _add_evidence_basis_schema(definitions)
    cast(dict[str, JsonValue], obligation_item["properties"]).update(
        {
            "evidence_basis": {"$ref": "#/$defs/obligation_evidence_basis"},
            "closure_basis": {"enum": list(_OBLIGATION_CLOSURE_BASES), "type": "string"},
            "closure_class": {"enum": list(_OBLIGATION_CLOSURE_CLASSES), "type": "string"},
        }
    )
    cast(list[JsonValue], obligation_item.setdefault("allOf", [])).append(
        {
            "if": {"anyOf": [{"required": ["closure_class"]}, {"required": ["closure_basis"]}]},
            "then": {"required": ["closure_basis", "closure_class"]},
        }
    )


def _add_evidence_basis_schema(definitions: dict[str, JsonValue]) -> None:
    """Typed read shape, with exact wire identities and separate omission categories (#1205)."""
    from finishup.protocol.models import StatusObligationEvidenceModel

    root = cast(dict[str, JsonValue], TypeAdapter(StatusObligationEvidenceModel).json_schema())
    nested = cast(dict[str, JsonValue], root.pop("$defs", {}))
    # Every prose leaf below uses the common, category-bound omission instead of these generic
    # Pydantic definitions. BeforeValidator-backed identities need the real wire definitions too.
    nested.pop("DataCategory", None)
    nested.pop("OmittedContentModel", None)
    root.pop("title", None)
    definitions.update(nested)
    definitions["obligation_evidence_basis"] = root
    definitions.setdefault(
        "claim_id",
        {
            "type": "string",
            "pattern": r"^clm_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        },
    )

    def props(name: str) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue], cast(dict[str, JsonValue], definitions[name])["properties"]
        )

    def ref(name: str) -> dict[str, JsonValue]:
        return {"$ref": "#/$defs/" + name}

    def array_items(name: str, field: str, item: dict[str, JsonValue]) -> None:
        cast(dict[str, JsonValue], props(name)[field])["items"] = item

    props("StatusEvidenceClaimModel")["claim_ref"] = ref("claim_id")
    array_items(
        "StatusEvidenceClaimModel",
        "supporting_refs",
        {"anyOf": [ref("evidence_or_result_id"), ref("obligation_id")]},
    )
    array_items("obligation_evidence_basis", "action_refs", ref("action_id"))
    array_items("obligation_evidence_basis", "observed_refs", ref("evidence_or_result_id"))
    props("StatusEvidenceResultModel")["result_ref"] = ref("result_id")
    props("StatusEvidenceResultModel")["action_ref"] = {
        "anyOf": [ref("action_id"), {"type": "null"}]
    }
    array_items("StatusEvidenceResultModel", "evidence_refs", ref("evidence_id"))
    props("StatusEvidenceResultModel")["verification"] = ref("StatusEvidenceVerificationModel")
    props("StatusEvidenceAdviceModel")["response_event_id"] = ref("event_id")
    props("StatusEvidenceAdviceModel")["evidence_refs"] = {
        "type": "array",
        "maxItems": 8,
        "items": ref("evidence_or_result_id"),
    }
    props("StatusEvidenceAssessmentModel")["check_event_id"] = ref("event_id")
    props("StatusEvidenceAssessmentModel")["checked_frontier"] = ref("canonical_uint")
    props("StatusEvidenceAssessmentModel")["cited_refs"] = {
        "type": "array",
        "minItems": 1,
        "maxItems": 16,
        "uniqueItems": True,
        "items": ref("subject_id"),
    }
    cast(dict[str, JsonValue], definitions["StatusEvidenceAssessmentModel"])["allOf"] = [
        {
            "if": {"properties": {"verdict": {"const": "not_assessable"}}, "required": ["verdict"]},
            "then": {"not": {"required": ["snippet"]}},
            "else": {"required": ["snippet"]},
        }
    ]
    props("StatusEvidenceResolutionModel")["finding_ref"] = ref("finding_id")
    for field in ("check_event_id", "resolved_by_check_event_id", "ruling_check_event_id"):
        props("StatusEvidenceResolutionModel")[field] = {
            "anyOf": [ref("event_id"), {"type": "null"}]
        }
    props("StatusEvidenceResolutionModel")["checked_frontier"] = {
        "anyOf": [ref("canonical_uint"), {"type": "null"}]
    }
    for name, field, category, limit in (
        ("StatusEvidenceAdviceModel", "summary", "finding_summary", 8192),
        ("StatusEvidenceAdviceModel", "detail", "finding_summary", 8192),
        ("StatusEvidenceAdviceModel", "reason", "decision_excerpt", 4096),
        ("StatusEvidenceAssessmentModel", "requirement_or_claim", "finding_summary", 8192),
        ("StatusEvidenceAssessmentModel", "snippet", "finding_summary", 8192),
    ):
        props(name)[field] = {
            "anyOf": [
                {"type": "string", "minLength": 1, "maxLength": limit},
                {
                    "allOf": [
                        {
                            "$ref": SCHEMA_NAMESPACE
                            + "common/operation-result-1.0.0.schema.json#/$defs/omitted_content"
                        },
                        {"properties": {"category": {"const": category}}, "required": ["category"]},
                    ]
                },
            ]
        }


def _add_status_semantic_progress(definitions: dict[str, JsonValue]) -> None:
    """Add optional structural AI-powered review progress to check operation pages (#571 A2)."""

    models = __import__(
        "finishup.protocol.models", fromlist=["SemanticProgressPhase", "SemanticReason"]
    )
    phases = [phase.value for phase in models.SemanticProgressPhase]
    # Job terminal codes. ``deferred_before_first_edit`` is a check-outcome reason
    # (check-result / check-recorded 1.5.0), never a durable-job terminal code, so it
    # stays out of this unreleased 1.4.0 enum (n6 item 4).
    reasons = sorted(
        (
            reason.value
            for reason in models.SemanticReason
            if reason
            not in {
                models.SemanticReason.DEFERRED_BEFORE_FIRST_EDIT,
                models.SemanticReason.ROUND_LIMIT_UNASSESSABLE,
            }
        ),
        key=lambda item: str(item).encode("ascii"),
    )
    terminal_fields: list[JsonValue] = [
        {"required": ["terminal_outcome"]},
        {"required": ["terminal_reason"]},
    ]
    definitions["semantic_progress"] = {
        "additionalProperties": False,
        "allOf": [
            {
                "if": {"properties": {"phase": {"const": "terminal"}}, "required": ["phase"]},
                "then": {
                    "not": {"required": ["remaining_ms"]},
                    "properties": {"condition": {"const": "terminal"}},
                    "required": ["terminal_outcome", "terminal_reason"],
                },
                "else": {
                    "not": {"anyOf": terminal_fields},
                    "properties": {"condition": {"enum": ["active", "overdue"]}},
                    "required": ["remaining_ms"],
                },
            }
        ],
        "properties": {
            "attempt_ordinal": {"$ref": "#/$defs/canonical_uint"},
            "condition": {"enum": ["active", "overdue", "terminal"], "type": "string"},
            "deadline_at": {"$ref": "#/$defs/timestamp"},
            "elapsed_ms": {"$ref": "#/$defs/canonical_uint"},
            "observed_at": {"$ref": "#/$defs/timestamp"},
            "phase": {"enum": cast(list[JsonValue], phases), "type": "string"},
            "phase_entered_at": {"$ref": "#/$defs/timestamp"},
            "queued_at": {"$ref": "#/$defs/timestamp"},
            "remaining_ms": {"$ref": "#/$defs/canonical_uint"},
            "terminal_outcome": {
                "enum": ["failed", "quarantined", "succeeded"],
                "type": "string",
            },
            "terminal_reason": {"enum": cast(list[JsonValue], reasons), "type": "string"},
        },
        "required": [
            "attempt_ordinal",
            "condition",
            "deadline_at",
            "elapsed_ms",
            "observed_at",
            "phase",
            "phase_entered_at",
            "queued_at",
        ],
        "type": "object",
    }
    operation_page = cast(dict[str, JsonValue], definitions["operation_page"])
    operation_properties = cast(dict[str, JsonValue], operation_page["properties"])
    operation_properties["semantic_progress"] = {"$ref": "#/$defs/semantic_progress"}
    # Issue #920: completed checks may disclose bounded opaque identities omitted by the
    # heuristic never-send class. Older operation rows omit this additive field.
    definitions["semantic_withheld_item"] = {
        "additionalProperties": False,
        "properties": {
            "item_id": {
                "maxLength": 128,
                "minLength": 1,
                "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
                "type": "string",
            },
            "reason": {"const": "never_send_heuristic"},
        },
        "required": ["item_id", "reason"],
        "type": "object",
    }
    operation_properties["semantic_withheld_items"] = {
        "items": {"$ref": "#/$defs/semantic_withheld_item"},
        "maxItems": 64,
        "type": "array",
        "uniqueItems": True,
    }
    operation_rules = cast(list[JsonValue], operation_page.setdefault("allOf", []))
    operation_rules.append(
        {
            "if": {"required": ["semantic_progress"]},
            "then": {
                "properties": {
                    "operation_kind": {"const": "check"},
                    "state": {"enum": ["pending", "complete"]},
                },
                "required": ["operation_kind", "state"],
            },
        }
    )
    _add_semantic_redacted_values(definitions, operation_properties)
    operation_rules.append(
        {
            "if": {"required": ["semantic_redacted_values"]},
            "then": {
                "properties": {
                    "operation_kind": {"const": "check"},
                    "state": {"const": "complete"},
                },
                "required": ["operation_kind", "state"],
            },
        }
    )
    operation_rules.append(
        {
            "if": {"required": ["semantic_withheld_items"]},
            "then": {
                "properties": {
                    "operation_kind": {"const": "check"},
                    "state": {"const": "complete"},
                },
                "required": ["operation_kind", "state"],
            },
        }
    )


def _add_status_observed_run(definitions: dict[str, JsonValue]) -> None:
    """Let a results row name its hook-observed run structurally (issue #909).

    The optional ``observed_run`` carries the 1-based occurrence among hook-observed results, the
    host tool name, the installation-keyed command commitment and the exit status. It never
    carries command text; the unreleased 1.4.0 results view gains it additively.
    """

    definitions["observed_run"] = {
        "additionalProperties": False,
        "properties": {
            "command_commitment": {
                "maxLength": 76,
                "minLength": 76,
                "pattern": r"^hmac-sha256:[0-9a-f]{64}$",
                "type": "string",
            },
            "exit_status": {"maximum": 2**31 - 1, "minimum": -(2**31), "type": "integer"},
            "occurrence": {"$ref": "#/$defs/positive_uint"},
            "tool_name": {
                "maxLength": 128,
                "minLength": 1,
                "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$",
                "type": "string",
            },
        },
        "required": ["occurrence"],
        "type": "object",
    }
    result_item = cast(dict[str, JsonValue], definitions["result_item"])
    result_properties = cast(dict[str, JsonValue], result_item["properties"])
    result_properties["observed_run"] = {"$ref": "#/$defs/observed_run"}
    result_rules = cast(list[JsonValue], result_item.setdefault("allOf", []))
    result_rules.append(
        {
            "if": {"required": ["observed_run"]},
            "then": {"properties": {"payload_available": {"const": True}}},
        }
    )


def _add_status_finding_frontier(definitions: dict[str, JsonValue]) -> None:
    """Add the optional record frontier every finding item carries (issue #917)."""

    finding_item = cast(dict[str, JsonValue], definitions["finding_item"])
    finding_properties = cast(dict[str, JsonValue], finding_item["properties"])
    finding_properties["finding_frontier"] = {
        "$ref": SCHEMA_NAMESPACE + "common/frontier-1.0.0.schema.json"
    }


def _add_status_operation_admission(definitions: dict[str, JsonValue]) -> None:
    """Add the optional pre-admission stage to absent operation pages (issue #838)."""

    definitions["check_admission"] = {
        "additionalProperties": False,
        "allOf": [
            {
                "if": {
                    "properties": {"refusal_count": {"const": "0"}},
                    "required": ["refusal_count"],
                },
                "then": {"properties": {"stage": {"const": "acquiring"}}},
            }
        ],
        "properties": {
            "elapsed_ms": {"$ref": "#/$defs/canonical_uint"},
            "first_observed_at": {"$ref": "#/$defs/timestamp"},
            "last_observed_at": {"$ref": "#/$defs/timestamp"},
            "observed_at": {"$ref": "#/$defs/timestamp"},
            "refusal_count": {"$ref": "#/$defs/canonical_uint"},
            "retry_after_ms": {"$ref": "#/$defs/canonical_uint"},
            "stage": {
                "enum": [
                    "acquiring",
                    "capture_handoff_pending",
                    "acquisition_contended",
                    "import_pending",
                ],
                "type": "string",
            },
        },
        "required": [
            "elapsed_ms",
            "first_observed_at",
            "last_observed_at",
            "observed_at",
            "refusal_count",
            "retry_after_ms",
            "stage",
        ],
        "type": "object",
    }
    operation_page = cast(dict[str, JsonValue], definitions["operation_page"])
    operation_properties = cast(dict[str, JsonValue], operation_page["properties"])
    operation_properties["admission"] = {"$ref": "#/$defs/check_admission"}
    operation_rules = cast(list[JsonValue], operation_page.setdefault("allOf", []))
    operation_rules.append(
        {
            "if": {"required": ["admission"]},
            "then": {
                "properties": {"found": {"const": False}, "state": {"const": "absent"}},
                "required": ["found", "state"],
            },
        }
    )


# Protocol 0.1 shipped as Yoetz and the product is now FinishUP (ADR-048). The released contracts
# fix the launcher head of every emitted command and the receipt package name to the pre-rename
# spelling; the unreleased versions below name the current spelling and still admit the legacy one
# a pre-rename development service emitted or a stored receipt carries.
def _admit_current_launcher_heads(definitions: dict[str, JsonValue]) -> None:
    """Widen each CHECK continuation command head to the current or the legacy launcher."""

    continuation = cast(dict[str, JsonValue], definitions["continuation"])
    for branch in cast(list[JsonValue], continuation["oneOf"]):
        properties = cast(dict[str, JsonValue], cast(dict[str, JsonValue], branch)["properties"])
        command = cast(dict[str, JsonValue], properties["command"])
        prefix = cast(list[JsonValue], command["prefixItems"])
        # Frozen legacy identifier (ADR-048): the released continuation head.
        if prefix[0] != {"const": "yoetz"}:
            raise SchemaGenerationError("continuation_command_head_changed")
        prefix[0] = {"enum": ["finishup", "yoetz"], "type": "string"}


def _admit_current_receipt_package_name(definitions: dict[str, JsonValue]) -> None:
    """Widen the receipt version slice package name to the current or the legacy distribution."""

    version_slice = cast(dict[str, JsonValue], definitions["version_slice"])
    properties = cast(dict[str, JsonValue], version_slice["properties"])
    # Frozen legacy identifier (ADR-048): the released receipt package name.
    if properties["package_name"] != {"const": "yoetz"}:
        raise SchemaGenerationError("receipt_package_name_changed")
    properties["package_name"] = {"enum": ["finishup", "yoetz"], "type": "string"}


def _receipt_document_v1_3_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Add the recorded child outcome section to the immutable receipt document."""

    document = _load_versioned_template(
        entry,
        "receipts/receipt-document-1.2.0.schema.json",
    )
    definitions = cast(dict[str, JsonValue], document["$defs"])
    receipt_properties = cast(dict[str, JsonValue], document["properties"])
    receipt_properties["correctness_advisory_counts"] = _advisory_counts_schema()
    receipt_properties["verification_coverage"] = _verification_coverage_schema()
    receipt_properties["semantic_status"] = {"const": "unavailable"}
    receipt_properties["semantic_reason"] = {"const": "round_limit_unassessable"}
    receipt_properties["disproved_self_verified_finding_ids"] = {
        "type": "array",
        "items": {"$ref": "#/$defs/finding_id"},
        "minItems": 1,
        "maxItems": 100,
        "uniqueItems": True,
    }
    document["dependentRequired"] = {
        "semantic_status": ["semantic_reason"],
        "semantic_reason": ["semantic_status"],
        "disproved_self_verified_finding_ids": ["self_verified_finding_ids"],
    }
    cast(list[JsonValue], document.setdefault("allOf", [])).append(
        {
            "if": {"required": ["semantic_status"]},
            "then": {
                "properties": {
                    "conclusion": {"enum": ["insufficient_coverage", "unresolved_findings_remain"]}
                },
                "not": {"required": ["semantic_provenance"]},
            },
        }
    )
    _admit_current_receipt_package_name(definitions)
    definitions["child_finding"] = _lineage_child_finding_schema()
    definitions["receipt_child"] = {
        "additionalProperties": False,
        "allOf": [
            {
                "if": {
                    "properties": {"outcome": {"const": "unavailable"}},
                    "required": ["outcome"],
                },
                "then": {"properties": {"tested_manifest_ref": {"type": "null"}}},
            }
        ],
        "properties": {
            "child_task_id": _lineage_id_schema("task_id"),
            "findings": {
                "items": {"$ref": "#/$defs/child_finding"},
                "maxItems": 100,
                "type": "array",
                "uniqueItems": True,
            },
            "freshness": {"enum": ["known", "unknown"], "type": "string"},
            "outcome": {
                "enum": ["annotated", "clean", "incomplete", "open_gap", "unavailable"],
                "type": "string",
            },
            "tested_manifest_ref": {"oneOf": [_lineage_id_schema("event_id"), {"type": "null"}]},
        },
        "required": [
            "child_task_id",
            "findings",
            "freshness",
            "outcome",
            "tested_manifest_ref",
        ],
        "type": "object",
    }
    # ``later_manifest_ref`` is nullable and optional in the domain model.
    cast(dict[str, JsonValue], definitions["receipt_child"])["properties"]["later_manifest_ref"] = {
        "oneOf": [_lineage_id_schema("event_id"), {"type": "null"}]
    }
    definitions["receipt_children"] = {
        "additionalProperties": False,
        "properties": {
            "children": {
                "items": {"$ref": "#/$defs/receipt_child"},
                "maxItems": 100,
                "type": "array",
                "uniqueItems": True,
            }
        },
        "required": ["children"],
        "type": "object",
    }
    receipt_response = cast(dict[str, JsonValue], definitions["receipt_response"])
    response_properties = cast(dict[str, JsonValue], receipt_response["properties"])
    _admit_terminal_dispositions(cast(dict[str, JsonValue], response_properties["disposition"]))
    cast(list[JsonValue], receipt_response["allOf"]).insert(1, _acknowledged_not_done_condition())
    _insert_before_waived(
        cast(list[JsonValue], receipt_response["allOf"]), _self_verified_condition()
    )
    # Issue #996: the link itself is disclosed by ids in ``duplicate_finding_links``.
    _admit_duplicate_of(
        response_properties, cast(list[JsonValue], receipt_response["allOf"]), link_field=False
    )
    properties = cast(dict[str, JsonValue], document["properties"])
    findings = cast(dict[str, JsonValue], properties["findings"])
    findings["items"] = {"$ref": SCHEMA_NAMESPACE + "findings/finding-1.4.0.schema.json"}
    properties["children"] = {"$ref": "#/$defs/receipt_children"}
    # Issue #905 terminal states, disclosed by id; present only when non-empty.
    # Issue #984: self-verified items (the agent verified a repair FinishUP could not prove).
    # Issue #1020: findings the reviewer repeated over the agent's reasoned rejection.
    for name in (
        "acknowledged_not_done_finding_ids",
        "rejection_accepted_finding_ids",
        "self_verified_finding_ids",
        "disputed_after_rebuttal_finding_ids",
        # tb4n3 RC-3 (ADR-046): a reviewer's limitation request the agent disclosed.
        "limitation_disclosed_finding_ids",
    ):
        properties[name] = {
            "items": {"$ref": "#/$defs/finding_id"},
            "maxItems": 100,
            "minItems": 1,
            "type": "array",
            "uniqueItems": True,
        }
    # Issue #995 (ADR-033): disclosed assumptions and verification limits, ids and a closed
    # kind only (the rationale stays in the decision); present only when non-empty.
    definitions["event_id"] = {
        "pattern": "^evt_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        "type": "string",
    }
    definitions["receipt_disclosure"] = {
        "additionalProperties": False,
        "properties": {
            "decision_event_id": {"$ref": "#/$defs/event_id"},
            "kind": {"enum": ["assumption", "verification_limit"], "type": "string"},
            "obligation_id": {"$ref": "#/$defs/obligation_id"},
        },
        "required": ["obligation_id", "kind", "decision_event_id"],
        "type": "object",
    }
    # Issue #984 (D7a): acknowledged findings whose premise the review disputes, by id.
    properties["premise_disputed_finding_ids"] = {
        "items": {"$ref": "#/$defs/finding_id"},
        "maxItems": 100,
        "minItems": 1,
        "type": "array",
        "uniqueItems": True,
    }
    # Issue #997 (ADR-032 slice C): obligations acknowledged as not done, disclosed by id.
    properties["acknowledged_not_done_obligation_ids"] = {
        "items": {"$ref": "#/$defs/obligation_id"},
        "maxItems": 100,
        "minItems": 1,
        "type": "array",
        "uniqueItems": True,
    }
    cast(list[JsonValue], document.setdefault("allOf", [])).append(
        {
            "if": {"required": ["acknowledged_not_done_obligation_ids"]},
            "then": {
                "properties": {
                    "conclusion": {"not": {"const": "no_unresolved_deterministic_findings"}}
                }
            },
        }
    )
    properties["disclosed_assumptions"] = {
        "items": {"$ref": "#/$defs/receipt_disclosure"},
        "maxItems": 64,
        "minItems": 1,
        "type": "array",
        "uniqueItems": True,
    }
    # Issue #996: holding ``duplicate_of`` links, ids only; present only when non-empty.
    definitions["duplicate_finding_link"] = {
        "additionalProperties": False,
        "properties": {
            "duplicate_of_finding_id": {"$ref": "#/$defs/finding_id"},
            "finding_id": {"$ref": "#/$defs/finding_id"},
        },
        "required": ["duplicate_of_finding_id", "finding_id"],
        "type": "object",
    }
    properties["duplicate_finding_links"] = {
        "items": {"$ref": "#/$defs/duplicate_finding_link"},
        "maxItems": 100,
        "minItems": 1,
        "type": "array",
        "uniqueItems": True,
    }
    # A repair only the agent verified never reads as clean (issue #984, ADR-034), nor does a
    # standing reviewer disagreement (issue #1020, ADR-040).
    for name in (
        "self_verified_finding_ids",
        "disputed_after_rebuttal_finding_ids",
        "limitation_disclosed_finding_ids",
    ):
        cast(list[JsonValue], document.setdefault("allOf", [])).append(
            {
                "if": {"required": [name]},
                "then": {
                    "properties": {
                        "conclusion": {"not": {"const": "no_unresolved_deterministic_findings"}}
                    }
                },
            }
        )
    # Issue #920: preserve only bounded opaque identities and the fixed heuristic reason in
    # receipt JSON. Empty arrays are omitted by the domain codec for historical byte stability.
    definitions["semantic_withheld_item"] = {
        "additionalProperties": False,
        "properties": {
            "item_id": {
                "maxLength": 128,
                "minLength": 1,
                "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
                "type": "string",
            },
            "reason": {"const": "never_send_heuristic"},
        },
        "required": ["item_id", "reason"],
        "type": "object",
    }
    properties["semantic_withheld_items"] = {
        "items": {"$ref": "#/$defs/semantic_withheld_item"},
        "maxItems": 64,
        "minItems": 1,
        "type": "array",
        "uniqueItems": True,
    }
    _add_semantic_redacted_values(definitions, properties, min_items=1)
    # Issue #1017: a gap a later check cleared stays on the record as ``historical`` with the
    # subject frontier of the first check that no longer carried it. Both fields appear together
    # and only on a historical gap; an absent status reads as live, so earlier bytes are kept.
    receipt_gap = cast(dict[str, JsonValue], definitions["receipt_gap"])
    gap_properties = cast(dict[str, JsonValue], receipt_gap["properties"])
    gap_properties["status"] = {"const": "historical"}
    gap_properties["cleared_at_frontier"] = _lineage_frontier_schema()
    receipt_gap["dependentRequired"] = {
        "cleared_at_frontier": ["status"],
        "status": ["cleared_at_frontier"],
    }
    # ADR-046: a live gap says whether it bounds the conclusion or is only disclosed; a clean
    # conclusion beside a bounding gap is a contradiction the schema refuses.
    gap_properties["effect"] = {"enum": ["bounds", "disclosed"], "type": "string"}
    cast(list[JsonValue], receipt_gap.setdefault("allOf", [])).append(
        {"if": {"required": ["status"]}, "then": {"not": {"required": ["effect"]}}}
    )
    # ADR-046: every rule behind the conclusion (the one that selected it first).
    definitions["conclusion_reason"] = {
        "additionalProperties": False,
        "properties": {
            "code": {"enum": list(_PREDICTION_REASON_CODES), "type": "string"},
            "count": {"maximum": 9007199254740991, "minimum": 1, "type": "integer"},
            "refs": {
                "items": {
                    "maxLength": 128,
                    "pattern": r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$",
                    "type": "string",
                },
                "maxItems": 3,
                "type": "array",
                "uniqueItems": True,
            },
            "rule": {
                "enum": ["R1", "R10", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9"],
                "type": "string",
            },
            "since_frontier": {"maximum": 9007199254740991, "minimum": 0, "type": "integer"},
        },
        "required": ["code", "count", "refs", "rule"],
        "type": "object",
    }
    properties["conclusion_basis"] = {
        "additionalProperties": False,
        "properties": {
            "reason_total": {"maximum": 9007199254740991, "minimum": 0, "type": "integer"},
            "reasons": {
                "items": {"$ref": "#/$defs/conclusion_reason"},
                "maxItems": 8,
                "type": "array",
            },
        },
        "required": ["reason_total", "reasons"],
        "type": "object",
    }
    required = cast(list[JsonValue], document["required"])
    if "children" not in required:
        required.append("children")
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    document["title"] = f"Yoetz receipt document {entry.schema_version}"
    return document


def _receipt_result_v1_3_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    document = _simple_versioned_schema(
        entry,
        "operations/receipt-result-1.2.0.schema.json",
        {"receipt-document-1.2.0": "receipt-document-1.3.0"},
    )
    _admit_current_receipt_package_name(cast(dict[str, JsonValue], document["$defs"]))
    definitions = cast(dict[str, JsonValue], document["$defs"])
    success = cast(dict[str, JsonValue], definitions["success"])
    cast(dict[str, JsonValue], success["properties"])["correctness_advisory_counts"] = (
        _advisory_counts_schema()
    )
    return document


def _publish_work_request_v1_2_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    document = _simple_versioned_schema(
        entry,
        "operations/publish-work-request-1.1.0.schema.json",
        {"event-draft-1.1.0": "event-draft-1.2.0"},
    )
    # Issue #1084, unreleased in-place change: an omitted ``expected_frontier`` is guarded by the
    # frontier the service reads when it admits the batch. ``request_id`` stays required: the
    # operation identity is caller- or host-owned (the MCP bridge and the CLI mint one for an agent
    # call that omits it), never derived by the service. A request that sends both is unchanged.
    required = cast(list[JsonValue], document["required"])
    document["required"] = [name for name in required if name != "expected_frontier"]
    return document


def _result_recorded_v1_1_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Add an optional agent-declared verification manifest without moving the released shape."""

    document = _load_versioned_template(entry, "events/result-recorded-1.0.0.schema.json")
    properties = cast(dict[str, JsonValue], document["properties"])
    properties["verification"] = {
        "type": "object",
        "additionalProperties": False,
        "required": ["criterion_quote", "data_source", "cases", "failing"],
        "properties": {
            "criterion_quote": {
                "type": "string",
                "minLength": 1,
                "maxLength": 240,
                "pattern": r"\S",
            },
            "data_source": {
                "type": "string",
                "enum": [
                    "task_public",
                    "own_generated",
                    "independent",
                    "held_out",
                    "stated_environment",
                    "unknown",
                ],
            },
            "cases": {"type": "integer", "minimum": 0, "maximum": 9007199254740991},
            "failing": {"type": "integer", "minimum": 0, "maximum": 9007199254740991},
            "worst": {"type": "string", "minLength": 1, "maxLength": 64, "pattern": r"\S"},
            "tuned_on_these_cases": {"type": "boolean"},
            "test_file": {"type": "string", "minLength": 1, "maxLength": 1024, "pattern": r"\S"},
            "results_file": {"type": "string", "minLength": 1, "maxLength": 1024, "pattern": r"\S"},
            "report_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            # Issue #1219: optional agent declarations, admitted in place on this unreleased
            # version. Absent, the manifest and every projection keep their earlier bytes.
            "checks": {"type": "string", "minLength": 1, "maxLength": 200, "pattern": r"\S"},
            "expected_from": {"type": "string", "enum": list(VERIFICATION_EXPECTED_FROM)},
        },
        # Issue #1226 (owner decision, in place on this unreleased version): ``test_file`` alone
        # declares the test the reviewer may be offered; ``results_file`` and ``report_digest``
        # bind a report to it and stay paired with each other (both or neither).
        "dependentRequired": {
            "results_file": ["test_file", "report_digest"],
            "report_digest": ["test_file", "results_file"],
        },
        "description": "Optional agent-declared test scope. The service checks the exact task quote and failing <= cases; this is advisory evidence, never proof of coverage.",
    }
    document["title"] = f"Yoetz result recorded {entry.schema_version}"
    return document


def _decision_recorded_v1_1_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Add ``review_mode`` or ``advisory_response`` to the released decision shape.

    Derived from the frozen 1.0.0 bytes; every other field is unchanged. A decision rides 1.1.0
    iff it switches the conversation's review mode (ADR-049) or records a non-blocking
    correctness-advisory response (ADR-006, #1162), so 1.1.0 requires exactly one of the two.
    1.1.0 is unreleased and amended in place under the same rule as check-recorded 1.6.0.
    """

    document = _load_versioned_template(entry, "events/decision-recorded-1.0.0.schema.json")
    properties = cast(dict[str, JsonValue], document["properties"])
    properties["review_mode"] = {"enum": ["ai_powered", "local"], "type": "string"}
    properties["advisory_response"] = _advisory_response_schema()
    document["oneOf"] = [
        {"required": ["review_mode"], "not": {"required": ["advisory_response"]}},
        {"required": ["advisory_response"], "not": {"required": ["review_mode"]}},
    ]
    from finishup.domain.correctness_advisories import ADVISORY_RESPONSE_STATEMENT

    document["allOf"] = [
        {
            "if": {"required": ["advisory_response"]},
            "then": {
                "properties": {
                    "statement": {"const": ADVISORY_RESPONSE_STATEMENT},
                    "rationale": {"minLength": 1, "maxLength": 4096},
                },
                "not": {
                    "anyOf": [
                        {"required": [key]}
                        for key in (
                            "alternatives",
                            "affected_obligation_ids",
                            "supersedes_event_id",
                        )
                    ]
                },
            },
        }
    ]
    document["title"] = f"Yoetz decision recorded {entry.schema_version}"
    return document


def _obligation_published_v1_1_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Add the ``directory`` item kind and the optional item ``role`` (issue #1002).

    Derived from the released, frozen 1.0.0 bytes; every other field is unchanged, so a 1.0.0
    payload is also a valid 1.1.0 payload.
    """

    document = _load_versioned_template(entry, "events/obligation-published-1.0.0.schema.json")
    definitions = cast(dict[str, JsonValue], document["$defs"])
    item = cast(dict[str, JsonValue], definitions["requested_item"])
    properties = cast(dict[str, JsonValue], item["properties"])
    kinds = cast(list[JsonValue], cast(dict[str, JsonValue], properties["item_kind"])["enum"])
    if "directory" not in kinds:
        kinds.append("directory")
    properties["role"] = {"enum": ["input", "output"], "type": "string"}
    # A role names whether a path is read or delivered, so only path kinds admit it.
    item["allOf"] = [
        {
            "if": {"required": ["role"]},
            "then": {"properties": {"item_kind": {"enum": ["file", "directory"]}}},
        }
    ]
    # ``acknowledged_not_done`` (#1002/#996): the agent states it did not do the obligation and
    # why. The reason is required exactly for that status, as resolution refs are for resolved.
    payload_properties = cast(dict[str, JsonValue], document["properties"])
    status = cast(dict[str, JsonValue], payload_properties["status"])
    statuses = cast(list[JsonValue], status["enum"])
    if "acknowledged_not_done" not in statuses:
        statuses.append("acknowledged_not_done")
    payload_properties["acknowledged_not_done_reason"] = {
        "maxLength": 4096,
        "minLength": 1,
        "pattern": "\\S",
        "type": "string",
    }
    rules = cast(list[JsonValue], document["allOf"])
    rules.append(
        {
            "else": {"not": {"required": ["acknowledged_not_done_reason"]}},
            "if": {
                "properties": {"status": {"const": "acknowledged_not_done"}},
                "required": ["status"],
            },
            "then": {"required": ["acknowledged_not_done_reason"]},
        }
    )
    document["title"] = f"Yoetz obligation published {entry.schema_version}"
    return document


def _event_draft_v1_1_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    document = _event_draft_schema(entry)
    definitions = cast(dict[str, JsonValue], document["$defs"])
    branches = cast(list[JsonValue], document["oneOf"])
    for family in (
        "check_recorded",
        "finding_recorded",
        "session_opened",
        "session_resumed",
    ):
        definition_name = f"schema_identity_{family}_1_1"
        alias_name = f"{family}_1_1_schema"
        definitions[definition_name] = {
            "additionalProperties": False,
            "properties": {"name": {"const": family}, "version": {"const": "1.1.0"}},
            "required": ["name", "version"],
            "type": "object",
        }
        definitions[alias_name] = {"$ref": f"#/$defs/{definition_name}"}
        legacy_path = f"events/{family.replace('_', '-')}-1.0.0.schema.json"
        new_path = f"events/{family.replace('_', '-')}-1.1.0.schema.json"
        legacy_index = next(
            index
            for index, item in enumerate(branches)
            if isinstance(item, dict) and legacy_path in json.dumps(item)
        )
        branches.insert(
            legacy_index + 1,
            {
                "properties": {
                    "payload": {"$ref": SCHEMA_NAMESPACE + new_path},
                    "schema": {"$ref": f"#/$defs/{alias_name}"},
                },
                "required": ["schema", "payload"],
            },
        )
    return document


_OCCURRED_AT_DRAFT_V1_2_DESCRIPTION: Final = (
    "Optional caller-asserted event time (RFC 3339 UTC, millisecond precision). Omit it and the "
    "service records its own clock at publication instead, named in the result's server_filled. "
    "When you send it, use the best real time available, never an illustrative example; it is a "
    "claim. Ledger order uses ingestion sequence; receipt freshness is frontier-bound."
)


def _event_draft_v1_2_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Add lineage payload families while retaining every previously admitted event pair."""

    document = _event_draft_v1_1_schema(entry)
    definitions = cast(dict[str, JsonValue], document["$defs"])
    branches = cast(list[JsonValue], document["oneOf"])
    # ``_event_draft_v1_1_schema`` is intentionally derived from the frozen v1.0 template and
    # therefore points its opaque fallback at the v1.1 opaque schema.  The v1.2 draft must carry
    # that fallback forward as well; otherwise a known lineage event matches both its new branch
    # and the stale opaque branch, making the advertised publish request oneOf ambiguous.
    opaque_v11 = SCHEMA_NAMESPACE + "events/opaque-unknown-event-draft-1.1.0.schema.json"
    opaque_v12 = SCHEMA_NAMESPACE + "events/opaque-unknown-event-draft-1.2.0.schema.json"
    opaque_branch = next(
        (item for item in branches if isinstance(item, dict) and item.get("$ref") == opaque_v11),
        None,
    )
    if opaque_branch is None:
        raise SchemaGenerationError(
            "event_draft_schema_template_invalid", entries=(entry.relative_path,)
        )
    opaque_branch["$ref"] = opaque_v12

    def add_branch(family: str, version: str) -> None:
        suffix = "_".join(version.split(".")[:2])
        identity_name = f"schema_identity_{family}_{suffix}"
        alias_name = f"{family}_{suffix}_schema"
        definitions[identity_name] = {
            "additionalProperties": False,
            "properties": {"name": {"const": family}, "version": {"const": version}},
            "required": ["name", "version"],
            "type": "object",
        }
        definitions[alias_name] = {"$ref": f"#/$defs/{identity_name}"}
        payload_path = f"events/{family.replace('_', '-')}-{version}.schema.json"
        branches.append(
            {
                "properties": {
                    "payload": {"$ref": SCHEMA_NAMESPACE + payload_path},
                    "schema": {"$ref": f"#/$defs/{alias_name}"},
                },
                "required": ["schema", "payload"],
            }
        )

    add_branch("check_recorded", "1.2.0")
    add_branch("check_recorded", "1.3.0")
    add_branch("session_opened", "1.2.0")
    add_branch("finding_recorded", "1.2.0")
    add_branch("finding_recorded", "1.3.0")
    add_branch("response_recorded", "1.1.0")
    add_branch("result_recorded", "1.1.0")
    for family, version in _TASK_STATEMENT_EVENT_PAIRS:
        add_branch(family, version)
    for family, version in _OBLIGATION_EVENT_PAIRS:
        add_branch(family, version)
    for family in (
        "child_accepted",
        "child_dependencies_recorded",
        "child_rejected",
        "child_written_off",
        "delegation_cancelled",
        "delegation_declared",
        "work_abandoned",
        "work_cancelled",
        "work_closed",
        "work_written_off",
        "coordination_context_recorded",
        "coordination_obligation_declared",
        "coordination_disposition_recorded",
    ):
        add_branch(family, "1.0.0")
    # Issue #1084, unreleased in-place change: the service fills an omitted envelope value. It
    # mints ``event_id`` from the request identity, records its own clock as ``occurred_at``,
    # copies the payload mirrors into ``evidence_refs``/``artifact_refs`` and defaults
    # ``causal_parents`` to an empty set; the result's ``server_filled`` names each one.
    document["required"] = ["schema", "payload"]
    properties = cast(dict[str, JsonValue], document["properties"])
    occurred = cast(dict[str, JsonValue], properties["occurred_at"])
    occurred["description"] = _OCCURRED_AT_DRAFT_V1_2_DESCRIPTION
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    document["title"] = f"Yoetz event draft {entry.schema_version}"
    return document


def _opaque_unknown_event_v1_1_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    document = _opaque_unknown_event_draft_schema(entry)
    definitions = cast(dict[str, JsonValue], document["$defs"])
    unknown = cast(dict[str, JsonValue], definitions["unknown_event_schema"])
    exclusion = cast(dict[str, JsonValue], unknown["not"])
    values = cast(list[JsonValue], exclusion["anyOf"])
    for family in (
        "check_recorded",
        "finding_recorded",
        "session_opened",
        "session_resumed",
    ):
        values.append(
            {
                "additionalProperties": False,
                "properties": {"name": {"const": family}, "version": {"const": "1.1.0"}},
                "required": ["name", "version"],
                "type": "object",
            }
        )
    return document


def _opaque_unknown_event_v1_2_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Exclude the lineage event pairs from the opaque-event fallback."""

    document = _opaque_unknown_event_v1_1_schema(entry)
    definitions = cast(dict[str, JsonValue], document["$defs"])
    unknown = cast(dict[str, JsonValue], definitions["unknown_event_schema"])
    exclusion = cast(dict[str, JsonValue], unknown["not"])
    values = cast(list[JsonValue], exclusion["anyOf"])
    for family in ("check_recorded", "finding_recorded"):
        values.append(
            {
                "additionalProperties": False,
                "properties": {"name": {"const": family}, "version": {"const": "1.2.0"}},
                "required": ["name", "version"],
                "type": "object",
            }
        )
    values.append(
        {
            "additionalProperties": False,
            "properties": {"name": {"const": "session_opened"}, "version": {"const": "1.2.0"}},
            "required": ["name", "version"],
            "type": "object",
        }
    )
    values.append(
        {
            "additionalProperties": False,
            "properties": {"name": {"const": "finding_recorded"}, "version": {"const": "1.3.0"}},
            "required": ["name", "version"],
            "type": "object",
        }
    )
    values.append(
        {
            "additionalProperties": False,
            "properties": {"name": {"const": "check_recorded"}, "version": {"const": "1.3.0"}},
            "required": ["name", "version"],
            "type": "object",
        }
    )
    values.append(
        {
            "additionalProperties": False,
            "properties": {"name": {"const": "response_recorded"}, "version": {"const": "1.1.0"}},
            "required": ["name", "version"],
            "type": "object",
        }
    )
    for family, version in (
        *_TASK_STATEMENT_EVENT_PAIRS,
        *_OBLIGATION_EVENT_PAIRS,
        ("result_recorded", "1.1.0"),
    ):
        values.append(
            {
                "additionalProperties": False,
                "properties": {"name": {"const": family}, "version": {"const": version}},
                "required": ["name", "version"],
                "type": "object",
            }
        )
    for family in (
        "child_accepted",
        "child_dependencies_recorded",
        "child_rejected",
        "child_written_off",
        "delegation_cancelled",
        "delegation_declared",
        "work_abandoned",
        "work_cancelled",
        "work_closed",
        "work_written_off",
        "coordination_context_recorded",
        "coordination_obligation_declared",
        "coordination_disposition_recorded",
    ):
        values.append(
            {
                "additionalProperties": False,
                "properties": {"name": {"const": family}, "version": {"const": "1.0.0"}},
                "required": ["name", "version"],
                "type": "object",
            }
        )
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    document["title"] = f"Yoetz opaque unknown event draft {entry.schema_version}"
    return document


def _publish_work_request_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Derive v1.1 authoring from frozen v1.0 and select the v1.1 draft union."""

    source = (
        Path(__file__).resolve().parent.parent
        / "schemas/operations/publish-work-request-1.0.0.schema.json"
    )
    try:
        document = cast(dict[str, JsonValue], json.loads(source.read_bytes()))
        properties = cast(dict[str, JsonValue], document["properties"])
        event_drafts = cast(dict[str, JsonValue], properties["event_drafts"])
        items = cast(dict[str, JsonValue], event_drafts["items"])
    except (KeyError, OSError, TypeError, json.JSONDecodeError) as exc:
        raise SchemaGenerationError(
            "publish_work_request_schema_template_invalid", entries=(entry.relative_path,)
        ) from exc
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    document["title"] = "Yoetz publish-work request 1.1.0"
    items["$ref"] = SCHEMA_NAMESPACE + "events/event-draft-1.1.0.schema.json"
    return document


def _review_packet_row_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """The inner items[] rows of yoetz.review-packet-case/2, not the outer egress case."""

    source = _load_versioned_template(entry, "privacy/outbound-case-1.2.0.schema.json")
    definitions = cast(dict[str, JsonValue], source["$defs"])
    item = cast(dict[str, JsonValue], definitions["content_item"])
    from finishup.domain.privacy import DataCategory

    definitions["data_category"] = {
        "type": "string",
        "enum": [category.value for category in DataCategory],
    }
    properties = dict(cast(dict[str, JsonValue], item["properties"]))
    properties.update(
        content_bytes={"type": "integer", "minimum": 0, "maximum": 131072},
        occurred_order={"type": "integer", "minimum": 0},
        latest_for={"$ref": "#/$defs/opaque_ref"},
        superseded_by={"$ref": "#/$defs/subject_refs"},
        follow_up_supplied={"type": "boolean", "const": True},
        transformations={
            "type": "array",
            "minItems": 1,
            "maxItems": 16,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "before_bytes": {"type": "integer", "minimum": 0},
                    "after_bytes": {"type": "integer", "minimum": 0},
                    "kind": {"const": "redacted"},
                    "reason": {"const": "sensitive_redacted"},
                },
                "required": ["before_bytes", "after_bytes", "kind", "reason"],
            },
        },
    )
    return _normalize(
        {
            "type": "object",
            "additionalProperties": False,
            "description": "Provider-bound items[] row for yoetz.review-packet-case/2. The builder emits follow_up_supplied only as true; absence remains compatible with older rows.",
            "$defs": {
                key: definitions[key]
                for key in (
                    "data_category",
                    "digest",
                    "item_id",
                    "opaque_ref",
                    "subject_refs",
                    "subject_ref",
                )
            },
            "properties": properties,
            "required": [
                "category",
                "content",
                "content_bytes",
                "content_digest",
                "item_id",
                "linked_subject_refs",
                "occurred_order",
                "section",
                "source_kind",
                "source_ref",
            ],
            "allOf": [
                {
                    "if": {"required": ["follow_up_supplied"]},
                    "then": {"properties": {"section": {"const": "excerpt"}}},
                }
            ],
        },
        entry,
    )


def _outbound_case_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Add observation provenance to outbound-case v1.1 without rewriting v1.0."""

    source = (
        Path(__file__).resolve().parent.parent / "schemas/privacy/outbound-case-1.0.0.schema.json"
    )
    try:
        document = cast(dict[str, JsonValue], json.loads(source.read_bytes()))
        definitions = cast(dict[str, JsonValue], document["$defs"])
        excerpt = cast(dict[str, JsonValue], definitions["targeted_excerpt"])
        excerpt_properties = cast(dict[str, JsonValue], excerpt["properties"])
        provenance = cast(dict[str, JsonValue], excerpt_properties["digest_provenance"])
        provenance_properties = cast(dict[str, JsonValue], provenance["properties"])
        provenance_enum = cast(dict[str, JsonValue], provenance_properties["provenance"])
        properties = cast(dict[str, JsonValue], document["properties"])
    except (KeyError, OSError, TypeError, json.JSONDecodeError) as exc:
        raise SchemaGenerationError(
            "outbound_case_schema_template_invalid", entries=(entry.relative_path,)
        ) from exc
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    document["title"] = f"Yoetz outbound case {entry.schema_version}"
    properties["schema_version"] = {"const": entry.schema_version}
    provenance_enum["enum"] = [
        "approved_check",
        "caller_asserted",
        "import_observed",
        "observation_captured",
    ]
    return document


def _outbound_case_v1_2_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Add the prior-findings review section to outbound-case v1.2 (issue #905).

    The section carries earlier AI-powered findings and the agent's answers under the existing
    finding categories, so no new data category crosses egress; only the section name, the
    packet's id list and its one-entry-per-finding rulable list are new.
    """

    from finishup.ports.semantic import MAX_PRIOR_FINDING_ITEMS, MAX_PRIOR_FINDING_REFS

    document = _load_versioned_template(entry, "privacy/outbound-case-1.1.0.schema.json")
    try:
        definitions = cast(dict[str, JsonValue], document["$defs"])
        item = cast(dict[str, JsonValue], definitions["content_item"])
        item_properties = cast(dict[str, JsonValue], item["properties"])
        section = cast(dict[str, JsonValue], item_properties["section"])
        sections = cast(list[JsonValue], section["enum"])
        packet = cast(dict[str, JsonValue], definitions["review_packet"])
        packet_properties = cast(dict[str, JsonValue], packet["properties"])
        packet_required = cast(list[JsonValue], packet["required"])
        properties = cast(dict[str, JsonValue], document["properties"])
    except (KeyError, TypeError) as exc:
        raise SchemaGenerationError(
            "outbound_case_schema_template_invalid", entries=(entry.relative_path,)
        ) from exc
    if "prior_finding" not in sections:
        sections.append("prior_finding")
        sections.sort(key=lambda value: str(value).encode("ascii"))
    if "verification_coverage" not in sections:
        sections.append("verification_coverage")
        sections.sort(key=lambda value: str(value).encode("ascii"))
    packet_properties["verification_coverage_item_ids"] = {
        "items": {"$ref": "#/$defs/item_id"},
        "maxItems": 1,
        "type": "array",
        "uniqueItems": True,
    }
    packet_properties["prior_finding_item_ids"] = {
        "items": {"$ref": "#/$defs/item_id"},
        "maxItems": MAX_PRIOR_FINDING_ITEMS,
        "minItems": 0,
        "type": "array",
        "uniqueItems": True,
    }
    if "prior_finding_item_ids" not in packet_required:
        packet_required.append("prior_finding_item_ids")
    # The rulable list: each carried earlier finding once, however many rows it has.
    packet_properties["prior_finding_refs"] = {
        "items": {"$ref": "#/$defs/finding_id"},
        "maxItems": MAX_PRIOR_FINDING_REFS,
        "minItems": 0,
        "type": "array",
        "uniqueItems": True,
    }
    if "prior_finding_refs" not in packet_required:
        packet_required.append("prior_finding_refs")
    # Issue #1220, optional in place: the agent's declared tests the packet lists, as structural
    # metadata (the declared path, the digest pinned at check time and the criterion ref).
    from finishup.kernel.declared_checks import DECLARED_TEST_EXPECTED_FROM

    packet_properties["declared_tests"] = {
        "items": {
            "additionalProperties": False,
            "properties": {
                "content_digest": {"$ref": "#/$defs/digest"},
                "criterion_ref": {"maxLength": 64, "minLength": 1, "type": "string"},
                # #1145, optional in place: the agent's own #1219 tag on the declaring manifest.
                "expected_from": {
                    "enum": cast(
                        list[JsonValue], sorted(DECLARED_TEST_EXPECTED_FROM, key=str.encode)
                    ),
                    "type": "string",
                },
                "path": {"maxLength": 256, "minLength": 1, "type": "string"},
                "ref": {"enum": ["dt1", "dt2", "dt3"], "type": "string"},
            },
            "required": ["content_digest", "criterion_ref", "path", "ref"],
            "type": "object",
        },
        "maxItems": 3,
        "minItems": 1,
        "type": "array",
    }
    _add_task_statement_to_outbound_case(document)
    _add_review_input_manifest_to_outbound_case(document)
    _add_test_check_to_review_input_manifest(document)
    properties["schema_version"] = {"const": entry.schema_version}
    document["title"] = f"Yoetz outbound case {entry.schema_version}"
    return document


def _add_test_check_to_review_input_manifest(document: dict[str, JsonValue]) -> None:
    """Issue #1220, optional in place on the unreleased current documents only (check-result and
    check-recorded 1.6.0 and later, status-result 1.4.0 and later, outbound-case 1.2.0): the packet
    listed the agent's declared tests; the listed files' pinned digests. Both or neither. A check
    whose manifest carries them is recorded as check-recorded 1.6.0, so the frozen 1.3.0 to 1.5.0
    bytes stay unchanged."""

    definitions = cast(dict[str, JsonValue], document["$defs"])
    manifest = cast(dict[str, JsonValue], definitions["review_input_manifest"])
    properties = cast(dict[str, JsonValue], manifest["properties"])
    properties["test_check_digests"] = {
        "items": {"pattern": "^sha256:[0-9a-f]{64}$", "type": "string"},
        "maxItems": 3,
        "minItems": 1,
        "type": "array",
        "uniqueItems": True,
    }
    properties["test_check_offered"] = {"const": True, "type": "boolean"}
    manifest["dependentRequired"] = {
        "test_check_digests": ["test_check_offered"],
        "test_check_offered": ["test_check_digests"],
    }


def _add_review_input_manifest_to_outbound_case(document: dict[str, JsonValue]) -> None:
    """Add the metadata-only composed/provider-bound input manifest (issues #951/#907)."""

    from finishup.ports.semantic import MAX_REVIEW_INPUT_SECTION_ITEMS, MAX_SEMANTIC_CASE_ITEMS
    from finishup.protocol.models import MAX_REVIEW_FOLLOW_UP_ROUNDS

    definitions = cast(dict[str, JsonValue], document["$defs"])
    # A section lists every selected item id. The prior-findings section alone can hold sixteen
    # findings of up to seven rows each (issue #976), so the list is bounded above 64.
    definitions["item_id_list_review_input_section"] = {
        "items": {"$ref": "#/$defs/opaque_ref"},
        "maxItems": MAX_REVIEW_INPUT_SECTION_ITEMS,
        "minItems": 0,
        "type": "array",
        "uniqueItems": True,
    }
    section_reasons = [
        "capture_unavailable",
        "content_unselected",
        "not_recorded",
        "not_selected",
        "redacted_never_send",
        "task_statement_not_authorized",
        "task_statement_not_supplied",
        "task_statement_unavailable",
        "truncated_payload",
        "withheld_by_policy",
    ]
    definitions["review_input_section"] = {
        "additionalProperties": False,
        "properties": {
            "content_bytes": {"maximum": 524288, "minimum": 0, "type": "integer"},
            "content_digest": {"oneOf": [{"$ref": "#/$defs/digest"}, {"type": "null"}]},
            "item_ids": {"$ref": "#/$defs/item_id_list_review_input_section"},
            "omission_reasons": {
                "items": {"enum": section_reasons, "type": "string"},
                "maxItems": 8,
                "type": "array",
                "uniqueItems": True,
            },
            "omitted_refs": {
                "items": {"$ref": "#/$defs/opaque_ref"},
                "maxItems": 16,
                "type": "array",
                "uniqueItems": True,
            },
            "revision": {
                "oneOf": [
                    {"maximum": 9007199254740991, "minimum": 0, "type": "integer"},
                    {"type": "null"},
                ]
            },
            "source_refs": {
                "items": {"$ref": "#/$defs/opaque_ref"},
                "maxItems": 16,
                "type": "array",
                "uniqueItems": True,
            },
            "status": {
                "enum": [
                    "complete",
                    "partial",
                    "title_only",
                    "missing",
                    "withheld",
                    "not_selected",
                ],
                "type": "string",
            },
        },
        "required": [
            "content_bytes",
            "content_digest",
            "item_ids",
            "omission_reasons",
            "omitted_refs",
            "revision",
            "source_refs",
            "status",
        ],
        "type": "object",
    }
    definitions["review_input_missing"] = {
        "additionalProperties": False,
        "properties": {
            "kind": {
                "enum": [
                    "command_identity",
                    "current_diff_for_path",
                    "other",
                    "plan_or_claim_text",
                    "prior_finding_context",
                    "task_statement",
                    "verification_output",
                ],
                "type": "string",
            },
            "status": {
                "enum": ["pending", "supplied", "unavailable", "repeated"],
                "type": "string",
            },
            "supplied_refs": {
                "items": {"$ref": "#/$defs/opaque_ref"},
                "maxItems": 4,
                "type": "array",
                "uniqueItems": True,
            },
            "target_refs": {
                "items": {"$ref": "#/$defs/opaque_ref"},
                "maxItems": 4,
                "type": "array",
                "uniqueItems": True,
            },
        },
        "required": ["kind", "status", "supplied_refs", "target_refs"],
        "type": "object",
    }
    definitions["review_input_manifest"] = {
        "additionalProperties": False,
        "properties": {
            name: {"$ref": "#/$defs/review_input_section"}
            for name in (
                "specification",
                "current_diff",
                "caller_evidence",
                "latest_verification",
                "prior_finding_context",
            )
        }
        | {
            # Issue #1047, optional in place: the in-check follow-up round this packet is.
            "follow_up_round": {
                "maximum": MAX_REVIEW_FOLLOW_UP_ROUNDS,
                "minimum": 1,
                "type": "integer",
            },
            "missing_inputs": {
                "items": {"$ref": "#/$defs/review_input_missing"},
                "maxItems": 8,
                "type": "array",
            },
            "omitted_item_count": {"maximum": 64, "minimum": 0, "type": "integer"},
            # Issue #976 (tb4n1 D11), optional in place: every distinct omission before the
            # listed rows were capped, so the count no longer saturates at 64.
            "omitted_item_total": {"maximum": 1048576, "minimum": 0, "type": "integer"},
            "phase": {"enum": ["composed", "provider_bound"], "type": "string"},
            # Issue #976, optional in place: the review phase the packet's question set named.
            "review_phase": {"enum": ["routine", "final"], "type": "string"},
            "schema": {"const": "yoetz.review-input-manifest/1", "type": "string"},
            "selected_excerpt_bytes": {"maximum": 524288, "minimum": 0, "type": "integer"},
            "selected_item_count": {
                "maximum": MAX_SEMANTIC_CASE_ITEMS,
                "minimum": 0,
                "type": "integer",
            },
        },
        "required": [
            "schema",
            "specification",
            "current_diff",
            "caller_evidence",
            "latest_verification",
            "prior_finding_context",
            "phase",
            "missing_inputs",
            "selected_item_count",
            "selected_excerpt_bytes",
            "omitted_item_count",
        ],
        "type": "object",
    }
    packet = cast(dict[str, JsonValue], definitions["review_packet"])
    packet_properties = cast(dict[str, JsonValue], packet["properties"])
    packet_properties["review_input_manifest"] = {"$ref": "#/$defs/review_input_manifest"}
    packet_properties["provider_input_manifest"] = {"$ref": "#/$defs/review_input_manifest"}


def _start_result_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Extend the reviewed start-result schema with its model-owned authoring scaffold.

    The start result deliberately uses shared external references and finite reviewed value
    shapes that Pydantic's generic projection does not preserve.  Keep that public contract as
    the template, while regenerating the additive projection-only scaffold here so ``--write``
    cannot replace the curated wire shape with framework-specific definitions.
    """

    source = Path(__file__).resolve().parent.parent / "schemas" / entry.relative_path
    try:
        document = cast(dict[str, JsonValue], json.loads(source.read_bytes()))
        definitions = cast(dict[str, JsonValue], document["$defs"])
        success = cast(dict[str, JsonValue], definitions["success"])
        properties = cast(dict[str, JsonValue], success["properties"])
        required = cast(list[JsonValue], success["required"])
        if not all(name in definitions for name in ("compact_view", "version_slice")):
            raise TypeError
    except (KeyError, OSError, TypeError, json.JSONDecodeError) as exc:
        raise SchemaGenerationError(
            "start_result_schema_template_invalid", entries=(entry.relative_path,)
        ) from exc

    empty_array: dict[str, JsonValue] = {
        "items": {"const": "", "type": "string"},
        "maxItems": 0,
        "type": "array",
    }

    def event_draft_template(schema_name: str, payload_ref: str) -> dict[str, JsonValue]:
        return {
            "additionalProperties": False,
            "properties": {
                "artifact_refs": dict(empty_array),
                "causal_parents": dict(empty_array),
                "event_id": {"const": "", "type": "string"},
                "evidence_refs": dict(empty_array),
                "occurred_at": {"const": "", "type": "string"},
                "payload": {"$ref": payload_ref},
                "schema": {
                    "additionalProperties": False,
                    "properties": {
                        "name": {"const": schema_name, "type": "string"},
                        "version": {"const": "1.0.0", "type": "string"},
                    },
                    "required": ["name", "version"],
                    "type": "object",
                },
            },
            "required": [
                "artifact_refs",
                "causal_parents",
                "event_id",
                "evidence_refs",
                "occurred_at",
                "payload",
                "schema",
            ],
            "type": "object",
        }

    definitions.update(
        cast(
            dict[str, JsonValue],
            {
                "start_next_request_actor_template": {
                    "additionalProperties": False,
                    "properties": {
                        "actor_id": {"const": "", "type": "string"},
                        "actor_type": {"const": "", "type": "string"},
                    },
                    "required": ["actor_id", "actor_type"],
                    "type": "object",
                },
                "start_next_request_client_template": {
                    "additionalProperties": False,
                    "properties": {
                        "integration": {"const": "", "type": "string"},
                        "kind": {"const": "", "type": "string"},
                        "version": {"const": "", "type": "string"},
                    },
                    "required": ["integration", "kind", "version"],
                    "type": "object",
                },
                "start_next_request_plan_payload_template": {
                    "additionalProperties": False,
                    "properties": {
                        "obligation_refs": {
                            "items": {"const": "", "type": "string"},
                            "maxItems": 1,
                            "minItems": 1,
                            "type": "array",
                        },
                        "plan_version": {"const": 1, "type": "integer"},
                        "summary": {"const": "", "type": "string"},
                    },
                    "required": ["obligation_refs", "plan_version", "summary"],
                    "type": "object",
                },
                "start_next_request_obligation_payload_template": {
                    "additionalProperties": False,
                    "properties": {
                        "acceptance_criteria": {"const": "", "type": "string"},
                        "description": {"const": "", "type": "string"},
                        "evidence_expectation": {"const": "", "type": "string"},
                        "obligation_id": {"const": "", "type": "string"},
                        "status": {"const": "open", "type": "string"},
                    },
                    "required": [
                        "acceptance_criteria",
                        "description",
                        "evidence_expectation",
                        "obligation_id",
                        "status",
                    ],
                    "type": "object",
                },
                "start_next_request_plan_event_draft_template": event_draft_template(
                    "plan_published",
                    "#/$defs/start_next_request_plan_payload_template",
                ),
                "start_next_request_obligation_event_draft_template": event_draft_template(
                    "obligation_published",
                    "#/$defs/start_next_request_obligation_payload_template",
                ),
                "start_publish_work_request_template": {
                    "additionalProperties": False,
                    "properties": {
                        "actor": {"$ref": "#/$defs/start_next_request_actor_template"},
                        "client": {"$ref": "#/$defs/start_next_request_client_template"},
                        "event_drafts": {
                            "items": False,
                            "maxItems": 2,
                            "minItems": 2,
                            "prefixItems": [
                                {"$ref": ("#/$defs/start_next_request_plan_event_draft_template")},
                                {
                                    "$ref": (
                                        "#/$defs/start_next_request_obligation_event_draft_template"
                                    )
                                },
                            ],
                            "type": "array",
                        },
                        "expected_frontier": {
                            "$ref": (
                                "https://schemas.yoetz.dev/0.1/common/frontier-1.0.0.schema.json"
                            )
                        },
                        "protocol_version": {"const": "0.1", "type": "string"},
                        "request_id": {"const": "", "type": "string"},
                        "schema_version": {"const": "1.0.0", "type": "string"},
                        "session_id": {"$ref": "#/$defs/session_id"},
                        "writer_id": {"$ref": "#/$defs/writer_id"},
                    },
                    "required": [
                        "actor",
                        "client",
                        "event_drafts",
                        "expected_frontier",
                        "protocol_version",
                        "request_id",
                        "schema_version",
                        "session_id",
                        "writer_id",
                    ],
                    "type": "object",
                },
                "start_next_request_template": {
                    "additionalProperties": False,
                    "properties": {
                        "arguments": {"$ref": "#/$defs/start_publish_work_request_template"},
                        "evidential": {"const": False, "type": "boolean"},
                        "operation": {"const": "publish_work", "type": "string"},
                    },
                    "required": ["arguments", "evidential", "operation"],
                    "type": "object",
                },
            },
        )
    )
    properties["next_request_template"] = {"$ref": "#/$defs/start_next_request_template"}
    if "next_request_template" not in required:
        required.append("next_request_template")
    compact_view = cast(dict[str, JsonValue], definitions["compact_view"])
    compact_properties = cast(dict[str, JsonValue], compact_view["properties"])
    compact_required = cast(list[JsonValue], compact_view["required"])
    compact_properties["open_obligation_count"] = {
        "oneOf": [
            {"$ref": "#/$defs/safe_count"},
            {"type": "null"},
        ]
    }
    legacy_unanswered = compact_properties.pop("unresolved_finding_count", None)
    if legacy_unanswered is not None:
        compact_properties["unanswered_finding_count"] = legacy_unanswered
    compact_properties["receipt_blocking_finding_count"] = {
        "oneOf": [
            {"$ref": "#/$defs/safe_count"},
            {"type": "null"},
        ]
    }
    if "unresolved_finding_count" in compact_required:
        compact_required[compact_required.index("unresolved_finding_count")] = (
            "unanswered_finding_count"
        )
    if "receipt_blocking_finding_count" not in compact_required:
        unanswered_index = compact_required.index("unanswered_finding_count")
        compact_required.insert(unanswered_index + 1, "receipt_blocking_finding_count")
    return document


def _plan_payload_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Add the typed empty-scope declaration to the reviewed plan payload contract.

    The reviewed schemas carry identifier, collection, and conditional constraints that generic
    Pydantic introspection cannot reproduce. Preserve those constraints and make only the additive
    pre-release correction owned by the domain model.
    """

    source = Path(__file__).resolve().parent.parent / "schemas" / entry.relative_path
    try:
        document = cast(dict[str, JsonValue], json.loads(source.read_bytes()))
        definitions = cast(dict[str, JsonValue], document.setdefault("$defs", {}))
        properties = cast(dict[str, JsonValue], document["properties"])
    except (KeyError, OSError, TypeError, json.JSONDecodeError) as exc:
        raise SchemaGenerationError(
            "plan_payload_schema_template_invalid", entries=(entry.relative_path,)
        ) from exc

    definitions["no_obligations_reason"] = {
        "enum": [
            "no_material_change",
            "single_atomic_change",
            "exploratory_scope_unknown",
        ],
        "type": "string",
    }
    properties["no_obligations_reason"] = {"$ref": "#/$defs/no_obligations_reason"}
    return document


def _read_guidance_result_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Build the closed read-guidance result, including bounded page metadata."""

    raw: dict[str, object] = {
        "$defs": {
            "guidance_resource_uri": {
                # The exact catalog is enforced by the runtime model. Keep the advertised schema
                # compact: emitting every heading anchor as an enum would put the full guidance
                # index back into each host tool declaration (#969).
                "pattern": r"^(?:finishup|yoetz)://guidance/[a-z0-9.-]+\.md(?:#[a-z0-9-]+)?$",
                "type": "string",
            },
            "success": {
                "additionalProperties": False,
                "allOf": [
                    {
                        "if": {
                            "anyOf": [
                                {"required": [field]}
                                for field in (
                                    "document_id",
                                    "revision",
                                    "digest",
                                    "total_byte_count",
                                    "page",
                                    "page_size",
                                    "page_offset",
                                    "page_byte_count",
                                    "page_count",
                                    "complete",
                                    "continuation",
                                    "sections",
                                )
                            ]
                        },
                        "then": {
                            "required": [
                                "document_id",
                                "revision",
                                "digest",
                                "total_byte_count",
                                "page",
                                "page_size",
                                "page_offset",
                                "page_byte_count",
                                "page_count",
                                "complete",
                            ]
                        },
                    },
                    {
                        "if": {
                            "properties": {"complete": {"const": True}},
                            "required": ["complete"],
                        },
                        "then": {"not": {"required": ["continuation"]}},
                    },
                    {
                        "if": {
                            "properties": {"complete": {"const": False}},
                            "required": ["complete"],
                        },
                        "then": {"required": ["continuation"]},
                    },
                    {
                        # tb4n5: only page zero of a paged read names the resource's sections.
                        "if": {"required": ["sections"]},
                        "then": {"properties": {"page": {"const": "0"}}},
                    },
                ],
                "properties": {
                    "byte_count": {"maximum": 65536, "minimum": 0, "type": "integer"},
                    "complete": {"type": "boolean"},
                    "continuation": {"$ref": "#/$defs/continuation"},
                    "digest": {"$ref": "#/$defs/digest"},
                    "document_id": {"$ref": "#/$defs/guidance_resource_uri"},
                    "media_type": {"const": "text/markdown", "type": "string"},
                    "ok": {"const": True, "type": "boolean"},
                    "page": {"$ref": "#/$defs/canonical_uint"},
                    "page_byte_count": {"maximum": 65536, "minimum": 0, "type": "integer"},
                    "page_count": {"$ref": "#/$defs/canonical_positive_uint"},
                    "page_offset": {
                        "maximum": _MAX_GUIDANCE_DOCUMENT_BYTES,
                        "minimum": 0,
                        "type": "integer",
                    },
                    "page_size": {"$ref": "#/$defs/page_size"},
                    "revision": {"$ref": "#/$defs/digest"},
                    "sections": {
                        "items": {"$ref": "#/$defs/section"},
                        "maxItems": _MAX_GUIDANCE_SECTIONS,
                        "minItems": 1,
                        "type": "array",
                    },
                    "text": {"maxLength": 65536, "minLength": 0, "type": "string"},
                    "total_byte_count": {
                        "maximum": _MAX_GUIDANCE_DOCUMENT_BYTES,
                        "minimum": 0,
                        "type": "integer",
                    },
                    "uri": {"$ref": "#/$defs/guidance_resource_uri"},
                },
                "required": ["byte_count", "media_type", "ok", "text", "uri"],
                "type": "object",
            },
            "section": {
                "additionalProperties": False,
                "properties": {
                    "byte_count": {
                        "maximum": _MAX_GUIDANCE_DOCUMENT_BYTES,
                        "minimum": 0,
                        "type": "integer",
                    },
                    "uri": {"$ref": "#/$defs/guidance_resource_uri"},
                },
                "required": ["byte_count", "uri"],
                "type": "object",
            },
            "canonical_positive_uint": {
                "pattern": r"^(?:[1-9][0-9]{0,18})$",
                "type": "string",
            },
            "canonical_uint": {
                "pattern": r"^(?:0|[1-9][0-9]{0,18})$",
                "type": "string",
            },
            "continuation": {
                "additionalProperties": False,
                "properties": {
                    "digest": {"$ref": "#/$defs/digest"},
                    "page": {"$ref": "#/$defs/canonical_uint"},
                    "page_size": {"$ref": "#/$defs/page_size"},
                    "revision": {"$ref": "#/$defs/digest"},
                    "uri": {"$ref": "#/$defs/guidance_resource_uri"},
                },
                "required": ["digest", "page", "page_size", "revision", "uri"],
                "type": "object",
            },
            "digest": {"pattern": r"^sha256:[0-9a-f]{64}$", "type": "string"},
            "page_size": {
                "pattern": (
                    r"^(?:[4-9]|[1-9][0-9]{1,3}|1[0-5][0-9]{3}|16[0-2][0-9]{2}|"
                    r"163(?:[0-7][0-9]|8[0-3]|84))$"
                ),
                "type": "string",
            },
        },
        "oneOf": [
            {"$ref": "#/$defs/success"},
            {
                "$ref": (
                    f"{SCHEMA_NAMESPACE}common/operation-result-1.0.0.schema.json"
                    "#/$defs/failure_result"
                )
            },
        ],
    }
    return _normalize(raw, entry)


def _read_guidance_request_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Build the closed request with optional, non-null bounded-page selectors."""

    raw: dict[str, object] = {
        "$defs": {
            "GuidanceResourceUri": {
                # Runtime validation admits only the exact registered catalog. A pattern keeps
                # the 100+ bounded heading topics from inflating the host-visible input schema.
                "pattern": r"^(?:finishup|yoetz)://guidance/[a-z0-9.-]+\.md(?:#[a-z0-9-]+)?$",
                "type": "string",
            },
            "canonical_uint": {
                "pattern": r"^(?:0|[1-9][0-9]{0,18})$",
                "type": "string",
            },
            "digest": {"pattern": r"^sha256:[0-9a-f]{64}$", "type": "string"},
            "page_size": {
                "pattern": (
                    r"^(?:[4-9]|[1-9][0-9]{1,3}|1[0-5][0-9]{3}|16[0-2][0-9]{2}|"
                    r"163(?:[0-7][0-9]|8[0-3]|84))$"
                ),
                "type": "string",
            },
        },
        "additionalProperties": False,
        "description": (
            "Read one registered guidance document, or one bounded UTF-8-safe page. "
            "Omit page fields for the legacy full-document route."
        ),
        "properties": {
            "digest": {"$ref": "#/$defs/digest"},
            "page": {"$ref": "#/$defs/canonical_uint"},
            "page_size": {"$ref": "#/$defs/page_size"},
            "revision": {"$ref": "#/$defs/digest"},
            "uri": {
                "$ref": "#/$defs/GuidanceResourceUri",
                "description": "One registered URI such as finishup://guidance/workflow.md.",
            },
        },
        "required": ["uri"],
        "type": "object",
    }
    return _normalize(raw, entry)


_CONTROL_ID_PATTERNS: Final[Mapping[str, str]] = {
    "event_id": r"^evt_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    "object_id": r"^obj_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    "project_id": r"^prj_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    "receipt_id": r"^rcp_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    "request_id": r"^req_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    "session_id": r"^ses_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    "task_id": r"^tsk_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    "writer_id": r"^wri_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
}
_CONTROL_DIGEST_PATTERN: Final = r"^sha256:[0-9a-f]{64}$"
_CONTROL_COMMITMENT_PATTERN: Final = r"^hmac-sha256:[0-9a-f]{64}$"
_CONTROL_TIMESTAMP_PATTERN: Final = (
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z$"
)


def _control_id_schema(kind: str) -> dict[str, JsonValue]:
    return {"pattern": _CONTROL_ID_PATTERNS[kind], "type": "string"}


def _control_string_schema(*, minimum: int = 1, maximum: int = 128) -> dict[str, JsonValue]:
    return {"maxLength": maximum, "minLength": minimum, "type": "string"}


def _control_nullable(schema: dict[str, JsonValue]) -> dict[str, JsonValue]:
    return {"oneOf": [schema, {"type": "null"}]}


def _control_positive_integer_schema() -> dict[str, JsonValue]:
    return {
        "maximum": 2**53 - 1,
        "minimum": 1,
        "type": "integer",
    }


def _control_project_request_schema() -> dict[str, JsonValue]:
    """Return the closed CLI-only project command body used by active control 2.7."""

    text = _control_string_schema(maximum=65_536)
    request = _control_id_schema("request_id")
    task = _control_id_schema("task_id")
    project = _control_id_schema("project_id")
    commitment = {"pattern": _CONTROL_COMMITMENT_PATTERN, "type": "string"}
    member = {
        "oneOf": [
            _control_id_schema("task_id"),
            commitment,
        ]
    }
    event = _control_id_schema("event_id")
    positive = _control_positive_integer_schema()
    properties: dict[str, JsonValue] = {
        "audit_record_id": _control_nullable(event),
        "auto_grouping": _control_nullable({"type": "boolean"}),
        "description": _control_nullable(text),
        "expected_generation": _control_nullable(positive),
        "member_commitment_or_id": _control_nullable(member),
        "member_kind": _control_nullable(
            {"enum": ["repository", "task", "workspace"], "type": "string"}
        ),
        "member_repository_commitment": _control_nullable(commitment),
        "membership_generation": _control_nullable(positive),
        "operation": {
            "enum": [
                "amend",
                "create",
                "dissolve",
                "grant",
                "link",
                "opt_in",
                "opt_out",
                "revoke",
                "status",
                "unlink",
            ],
            "type": "string",
        },
        "owner_route_generation": _control_nullable(positive),
        "owner_task_id": _control_nullable(task),
        "project_id": _control_nullable(project),
        "repository_commitment": _control_nullable(commitment),
        "request_id": request,
        "requester_task_id": _control_nullable(task),
        "schema_version": {"const": "1.0.0"},
        "selected_task_id": _control_nullable(task),
        "source_workspace_commitment": _control_nullable(commitment),
        "title": _control_nullable(text),
    }

    def operation(
        name: str,
        required: tuple[str, ...],
        overrides: Mapping[str, JsonValue],
    ) -> dict[str, JsonValue]:
        return {
            "if": {
                "properties": {"operation": {"const": name}},
                "required": ["operation"],
            },
            "then": {
                "properties": dict(overrides),
                "required": list(required),
            },
        }

    conditions: list[JsonValue] = [
        operation(
            "create",
            ("title", "owner_task_id"),
            {"owner_task_id": task, "title": text},
        ),
        operation(
            "link",
            ("project_id", "member_kind", "member_commitment_or_id"),
            {
                "member_commitment_or_id": member,
                "member_kind": {"enum": ["repository", "task", "workspace"], "type": "string"},
                "project_id": project,
            },
        ),
        operation(
            "unlink",
            ("project_id", "member_kind", "member_commitment_or_id"),
            {
                "member_commitment_or_id": member,
                "member_kind": {"enum": ["repository", "task", "workspace"], "type": "string"},
                "project_id": project,
            },
        ),
        {
            "if": {
                "properties": {"operation": {"const": "amend"}},
                "required": ["operation"],
            },
            "then": {
                "anyOf": [
                    {"properties": {"title": text}, "required": ["title"]},
                    {"properties": {"description": text}, "required": ["description"]},
                ],
                "properties": {"owner_task_id": task, "project_id": project},
                "required": ["owner_task_id", "project_id"],
            },
        },
        operation("dissolve", ("project_id",), {"project_id": project}),
        operation(
            "opt_out",
            ("repository_commitment",),
            {"repository_commitment": commitment},
        ),
        operation(
            "opt_in",
            ("repository_commitment",),
            {"repository_commitment": commitment},
        ),
        operation(
            "grant",
            ("project_id", "membership_generation"),
            {"membership_generation": positive, "project_id": project},
        ),
        operation(
            "revoke",
            ("project_id", "membership_generation"),
            {"membership_generation": positive, "project_id": project},
        ),
        operation(
            "status",
            ("requester_task_id", "project_id"),
            {"project_id": project, "requester_task_id": task},
        ),
    ]
    return {
        "additionalProperties": False,
        "allOf": conditions,
        "properties": properties,
        "required": ["operation", "request_id", "schema_version"],
        "type": "object",
    }


def _control_project_result_schema() -> dict[str, JsonValue]:
    """Return the structural project result union used by CLI control responses."""

    digest = {"pattern": _CONTROL_DIGEST_PATTERN, "type": "string"}
    commitment = {"pattern": _CONTROL_COMMITMENT_PATTERN, "type": "string"}
    timestamp = {"format": "date-time", "pattern": _CONTROL_TIMESTAMP_PATTERN, "type": "string"}
    project = _control_id_schema("project_id")
    task = _control_id_schema("task_id")
    event = _control_id_schema("event_id")
    object_id = _control_id_schema("object_id")
    positive = {
        "maxLength": 19,
        "pattern": _LINEAGE_POSITIVE_UINT_PATTERN,
        "type": "string",
    }
    text_ref: dict[str, JsonValue] = {
        "additionalProperties": False,
        "properties": {
            "content_digest": digest,
            "envelope_digest": _control_nullable(digest),
            "object_id": object_id,
            "owner_task_id": task,
            "plaintext_size": {"maximum": 4_194_304, "minimum": 0, "type": "integer"},
            "route_generation": positive,
        },
        "required": [
            "content_digest",
            "object_id",
            "owner_task_id",
            "plaintext_size",
            "route_generation",
        ],
        "type": "object",
    }
    descriptor: dict[str, JsonValue] = {
        "additionalProperties": False,
        "properties": {
            "auto_grouping": {"type": "boolean"},
            "created_at": timestamp,
            "description_ref": text_ref,
            "dissolved_at": timestamp,
            "kind": {"enum": ["general", "repository"], "type": "string"},
            "membership_generation": positive,
            "project_id": project,
            "repository_commitment": commitment,
            "title_ref": text_ref,
        },
        "required": [
            "auto_grouping",
            "created_at",
            "kind",
            "membership_generation",
            "project_id",
        ],
        "type": "object",
    }
    membership: dict[str, JsonValue] = {
        "additionalProperties": False,
        "properties": {
            "bound_at": timestamp,
            "member_commitment_or_id": {
                "oneOf": [task, commitment],
            },
            "member_kind": {"enum": ["repository", "task", "workspace"], "type": "string"},
            "membership_generation": positive,
            "project_id": project,
            "unbound_at": timestamp,
        },
        "required": [
            "bound_at",
            "member_commitment_or_id",
            "member_kind",
            "membership_generation",
            "project_id",
        ],
        "type": "object",
    }
    membership_view = {
        "allOf": [
            {"$ref": "#/$defs/project_membership"},
            {
                "properties": {
                    "actor_id": {"pattern": r"^[A-Za-z0-9._:-]{1,128}$", "type": "string"},
                    "parent_task_id": task,
                    "session_health": {
                        "enum": ["active", "contact_lost", "ended"],
                        "type": "string",
                    },
                    "task_id": task,
                    "work_state": {
                        "enum": ["abandoned", "cancelled", "closed", "open", "written_off"],
                        "type": "string",
                    },
                },
                "type": "object",
            },
        ],
        "unevaluatedProperties": False,
    }
    grant: dict[str, JsonValue] = {
        "additionalProperties": False,
        "allOf": [
            {
                "if": {"properties": {"state": {"const": "active"}}, "required": ["state"]},
                "then": {"not": {"required": ["revoked_at"]}},
            },
            {
                "if": {"properties": {"state": {"const": "revoked"}}, "required": ["state"]},
                "then": {"required": ["revoked_at"]},
            },
        ],
        "properties": {
            "audit_record_id": event,
            "granted_at": timestamp,
            "membership_generation": positive,
            "project_id": project,
            "revoked_at": timestamp,
            "state": {"enum": ["active", "revoked"], "type": "string"},
        },
        "required": [
            "audit_record_id",
            "granted_at",
            "membership_generation",
            "project_id",
            "state",
        ],
        "type": "object",
    }
    detection: dict[str, JsonValue] = {
        "additionalProperties": False,
        "properties": {
            "detection_id": event,
            "open": {"type": "boolean"},
            "resource_count": {"maximum": 2**53 - 1, "minimum": 0, "type": "integer"},
            "task_ids": {
                "items": task,
                "maxItems": 64,
                "minItems": 2,
                "type": "array",
                "uniqueItems": True,
            },
        },
        "required": ["detection_id", "open", "resource_count", "task_ids"],
        "type": "object",
    }
    status: dict[str, JsonValue] = {
        "additionalProperties": False,
        "properties": {
            "authorized_task_id": task,
            "detections": {
                "items": detection,
                "maxItems": 100,
                "type": "array",
                "uniqueItems": True,
            },
            "grant": grant,
            "memberships": {
                "items": {"$ref": "#/$defs/project_membership_view"},
                "maxItems": 100,
                "type": "array",
                "uniqueItems": True,
            },
            "project": {"$ref": "#/$defs/project_descriptor"},
            "schema_version": {"const": "1.0.0"},
        },
        "required": ["detections", "memberships", "project", "schema_version"],
        "type": "object",
    }
    opt_result = {
        "additionalProperties": False,
        "properties": {
            "auto_grouping": {"type": "boolean"},
            "project_id": {"type": "null"},
            "repository_commitment": commitment,
            "schema_version": {"const": "1.0.0"},
        },
        "required": ["auto_grouping", "project_id", "repository_commitment", "schema_version"],
        "type": "object",
    }
    return {
        "$defs": {
            "project_descriptor": descriptor,
            "project_detection": detection,
            "project_grant": grant,
            "project_membership": membership,
            "project_membership_view": membership_view,
            "project_opt_result": opt_result,
            "project_status": status,
            "project_text_ref": text_ref,
        },
        "oneOf": [
            {"$ref": "#/$defs/project_descriptor"},
            {"$ref": "#/$defs/project_membership"},
            {"$ref": "#/$defs/project_grant"},
            {"$ref": "#/$defs/project_opt_result"},
            {"$ref": "#/$defs/project_status"},
        ],
    }


def _individual_observation_envelope(definitions: dict[str, JsonValue]) -> dict[str, JsonValue]:
    """Return the individual-observation branch of a control-request envelope definition.

    Since ``2.6.1`` the ``observation_envelope`` definition is a ``oneOf`` whose first branch is
    the individual native capture envelope and whose second is the closed routine-read-summary
    reference. Later contracts extend the individual branch only; the summary branch stays the
    reference to its own versioned schema.
    """

    envelope = cast(dict[str, JsonValue], definitions["observation_envelope"])
    branches = envelope.get("oneOf")
    if isinstance(branches, list):
        return cast(dict[str, JsonValue], cast(list[JsonValue], branches)[0])
    return envelope


def _control_v2_8_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Extend frozen 2.7 with native cooperative-child correlation candidates."""

    source = (
        Path(__file__).resolve().parent.parent
        / "schemas"
        / entry.relative_path.replace("2.8.0", "2.7.0")
    )
    document = cast(dict[str, JsonValue], json.loads(source.read_bytes()))
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    if entry.schema_name == "control-request":
        definitions = cast(dict[str, JsonValue], document["$defs"])
        envelope = _individual_observation_envelope(definitions)
        properties = cast(dict[str, JsonValue], envelope["properties"])
        structural = cast(dict[str, JsonValue], properties["structural_payload"])
        fields = cast(dict[str, JsonValue], structural["properties"])
        fields.update(
            {
                "lineage_child_task_id": _control_id_schema("task_id"),
                "lineage_child_session_id": _control_id_schema("session_id"),
                "lineage_child_writer_id": _control_id_schema("writer_id"),
                "lineage_parent_task_id": _control_id_schema("task_id"),
            }
        )
    return document


# The finite structural-queue bounds a 2.9 selection runtime may report (issue #828).  Mirrored
# from ``finishup.domain.observation_budget`` as reviewable literals rather than imported.
_OBSERVATION_CAPACITY_MINIMUM: Final = 64
_OBSERVATION_CAPACITY_MAXIMUM: Final = 8_192
_OBSERVATION_CAPACITY_LABELS: Final[tuple[str, ...]] = ("standard", "larger", "largest", "custom")
_OBSERVATION_BUDGET_LIMIT_KEYS: Final[tuple[str, ...]] = (
    "queue_count",
    "queue_bytes",
    "state_bytes",
    "pending_attempts",
    "capture_tickets",
    "capture_bytes",
    "protected_count",
    "protected_bytes",
    "session_fair_share",
    "session_fair_share_bytes",
    "max_pending_age_ms",
    "state_document_ceiling_bytes",
)


def _observation_capacity_count_schema() -> dict[str, JsonValue]:
    return {
        "maximum": _OBSERVATION_CAPACITY_MAXIMUM,
        "minimum": _OBSERVATION_CAPACITY_MINIMUM,
        "type": "integer",
    }


def _observation_capacity_label_schema() -> dict[str, JsonValue]:
    return {"enum": list(_OBSERVATION_CAPACITY_LABELS), "type": "string"}


def _observation_nonnegative_integer_schema() -> dict[str, JsonValue]:
    return {"maximum": 9_007_199_254_740_991, "minimum": 0, "type": "integer"}


def _observation_effective_budget_schema(
    token: Mapping[str, JsonValue],
) -> dict[str, JsonValue]:
    """Return the closed ``yoetz.observation-effective-budget/1`` record definition."""

    limits: dict[str, JsonValue] = {
        "additionalProperties": False,
        "properties": {
            key: _observation_nonnegative_integer_schema() for key in _OBSERVATION_BUDGET_LIMIT_KEYS
        },
        "required": list(_OBSERVATION_BUDGET_LIMIT_KEYS),
        "type": "object",
    }
    no_cap: dict[str, JsonValue] = {
        "additionalProperties": False,
        "properties": {
            "available": {"const": False},
            "dimension": {"const": "structural_queue"},
            "reason": {"const": "state_document_ceiling"},
            "state_document_ceiling_bytes": _observation_nonnegative_integer_schema(),
            "largest_supported_queue_count": _observation_nonnegative_integer_schema(),
        },
        "required": [
            "available",
            "dimension",
            "reason",
            "state_document_ceiling_bytes",
            "largest_supported_queue_count",
        ],
        "type": "object",
    }
    properties: dict[str, JsonValue] = {
        "schema": {"const": "yoetz.observation-effective-budget/1"},
        "budget_policy_version": dict(token),
        "validation_status": dict(token),
        "scope": {"enum": ["session", "workspace"], "type": "string"},
        "selected_queue_count": _observation_capacity_count_schema(),
        "selected_capacity_label": _observation_capacity_label_schema(),
        "effective_queue_count": _observation_capacity_count_schema(),
        "effective_capacity_label": _observation_capacity_label_schema(),
        "effective_reason": {"enum": ["selected", "workspace_aggregate"], "type": "string"},
        "limits": limits,
        "limiting_dimension": {
            "enum": ["count", "bytes", "oldest_age", "capture_backlog"],
            "type": "string",
        },
        "utilization_bps": _observation_nonnegative_integer_schema(),
        "no_cap": no_cap,
    }
    return {
        "additionalProperties": False,
        "properties": properties,
        "required": list(properties),
        "type": "object",
    }


def _control_v2_9_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Extend frozen 2.8 with custom finite capacity and the effective-budget record (#828).

    ``control-result``: ``observation_selection_runtime`` accepts any finite structural-queue
    count in the supported range, names its capacity labels, and carries the closed
    effective-budget record.  ``control-request`` (unreleased 2.9.0, #909): an individual
    observation envelope may carry the installation-keyed ``command_commitment`` its hook computed
    from the command argument; it is an ``hmac-sha256:`` value, never command text.  The hello
    documents only move to the 2.9.0 ``$id``.
    """

    source = (
        Path(__file__).resolve().parent.parent
        / "schemas"
        / entry.relative_path.replace("2.9.0", "2.8.0")
    )
    document = cast(dict[str, JsonValue], json.loads(source.read_bytes()))
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    # 2.9.0 is unreleased on the 0.3 line: it also carries the respond 1.1.0 pair that admits the
    # terminal ``acknowledged_not_done`` disposition (#905).  Every earlier control version (the
    # released ones through 2.6.1 and the unreleased 2.7.0/2.8.0) keeps the frozen 1.0.0 pair, so
    # an older service refuses the new disposition at its own schema boundary.  It likewise carries
    # the publish-work 1.1.0 result whose version slice names the current policy-pack versions.
    respond_replacements = {
        SCHEMA_NAMESPACE + "operations/respond-request-1.0.0.schema.json": SCHEMA_NAMESPACE
        + "operations/respond-request-1.1.0.schema.json",
        SCHEMA_NAMESPACE + "operations/respond-result-1.0.0.schema.json": SCHEMA_NAMESPACE
        + "operations/respond-result-1.1.0.schema.json",
        SCHEMA_NAMESPACE + "operations/publish-work-result-1.0.0.schema.json": SCHEMA_NAMESPACE
        + "operations/publish-work-result-1.1.0.schema.json",
        SCHEMA_NAMESPACE + "privacy/egress-receipt-1.0.0.schema.json": SCHEMA_NAMESPACE
        + "privacy/egress-receipt-1.1.0.schema.json",
    }

    def retarget_respond(node: JsonValue) -> None:
        if isinstance(node, dict):
            for key, value in tuple(node.items()):
                if type(value) is str:
                    rewritten = value
                    for before, after in respond_replacements.items():
                        rewritten = rewritten.replace(before, after)
                    node[key] = rewritten
                else:
                    retarget_respond(value)
        elif isinstance(node, list):
            for value in node:
                retarget_respond(value)

    retarget_respond(document)
    # 2.9.0 is the active control envelope. Its embedded operation and receipt bodies must
    # follow the current public finding/check contracts; earlier control artifacts remain frozen.
    active_replacements = {
        SCHEMA_NAMESPACE + "operations/check-result-1.3.0.schema.json": SCHEMA_NAMESPACE
        + "operations/check-result-1.7.0.schema.json",
        SCHEMA_NAMESPACE + "findings/finding-1.3.0.schema.json": SCHEMA_NAMESPACE
        + "findings/finding-1.4.0.schema.json",
        SCHEMA_NAMESPACE + "operations/status-request-1.2.0.schema.json": SCHEMA_NAMESPACE
        + "operations/status-request-1.3.0.schema.json",
        SCHEMA_NAMESPACE + "operations/status-result-1.4.0.schema.json": SCHEMA_NAMESPACE
        + "operations/status-result-1.5.0.schema.json",
        SCHEMA_NAMESPACE + "operations/receipt-result-1.3.0.schema.json": SCHEMA_NAMESPACE
        + "operations/receipt-result-1.4.0.schema.json",
    }

    def retarget_active(node: JsonValue) -> None:
        if isinstance(node, dict):
            for key, value in tuple(node.items()):
                if type(value) is str:
                    node[key] = active_replacements.get(value, value)
                else:
                    retarget_active(value)
        elif isinstance(node, list):
            for value in node:
                retarget_active(value)

    retarget_active(document)
    # The active control result carries both network and local receipts.  Extend its inline local
    # shape with the same additive scan/omission vocabulary as the external receipt schema.
    if entry.schema_name == "control-result":
        definitions = cast(dict[str, JsonValue], document["$defs"])
        local_receipt = definitions.get("local_disclosure_receipt")
        if not isinstance(local_receipt, dict):
            raise SchemaGenerationError(
                "control_local_receipt_schema_template_invalid", entries=(entry.relative_path,)
            )
        egress_source = (
            Path(__file__).resolve().parent.parent
            / "schemas/privacy/egress-receipt-1.0.0.schema.json"
        )
        try:
            egress_template = cast(dict[str, JsonValue], json.loads(egress_source.read_bytes()))
            reason_schema = cast(
                dict[str, JsonValue],
                cast(dict[str, JsonValue], egress_template["$defs"])["privacy_reason"],
            )
        except (OSError, TypeError, json.JSONDecodeError, KeyError) as exc:
            raise SchemaGenerationError(
                "control_local_receipt_schema_template_invalid", entries=(entry.relative_path,)
            ) from exc
        cast(dict[str, JsonValue], local_receipt["properties"])["schema_version"] = {
            "enum": ["1.0.0", "1.1.0"],
            "type": "string",
        }
        _extend_receipt_schema_fields(
            local_receipt,
            reason_schema=reason_schema,
            definitions=definitions,
        )
        _add_setup_credential_heuristic(definitions)
    if entry.schema_name == "control-request":
        definitions = cast(dict[str, JsonValue], document["$defs"])
        envelope = _individual_observation_envelope(definitions)
        properties = cast(dict[str, JsonValue], envelope["properties"])
        structural = cast(dict[str, JsonValue], properties["structural_payload"])
        fields = cast(dict[str, JsonValue], structural["properties"])
        fields["command_commitment"] = {
            "maxLength": 76,
            "minLength": 76,
            "pattern": _CONTROL_COMMITMENT_PATTERN,
            "type": "string",
        }
        # Every tool observation carries the command runner class the domain serializer derives;
        # without it the hook's ingest frame failed client validation and command observations
        # reached the ledger only through the delayed in-process sweep.
        fields["runner_class"] = {
            "enum": [
                "build",
                "compound",
                "exploration",
                "lint",
                "other",
                "test",
                "typecheck",
                "vcs",
            ],
            "type": "string",
        }
        # Closed runtime facts the hook derives at the host boundary (#977): where a package
        # install resolved its interpreter, an edit outside the workspace, the effective user.
        # ``write_scope`` also names an edit whose every path is scratch or FinishUP-owned (ADR-042),
        # the agent's own notes, and a shell command that writes the workspace (ADR-045). The enum
        # is the hook's own closed set: a value the hook emits and this wire refuses fails client
        # validation on every drain pass and never reaches the ledger (#1039).
        from finishup.domain.command_segments import MAX_COMMAND_COMMITMENTS
        from finishup.domain.write_scope import WRITE_SCOPES

        fields["install_target"] = {
            "enum": ["private_env", "system", "unresolved", "workspace_env", "yoetz_runtime"],
            "type": "string",
        }
        fields["write_scope"] = {
            "enum": cast(list[JsonValue], sorted(WRITE_SCOPES)),
            "type": "string",
        }
        fields["effective_user"] = {"enum": ["non_root", "root"], "type": "string"}
        # Whether the hook's before/after workspace fingerprint saw the call change the workspace
        # (PR #1080 round 5): the hook's own closed set, read from the domain module.
        from finishup.domain.workspace_effect import WORKSPACE_EFFECTS

        fields["workspace_effect"] = {
            "enum": cast(list[JsonValue], sorted(WORKSPACE_EFFECTS)),
            "type": "string",
        }
        from finishup.domain.workspace_effect import MAX_CHANGED_ENTRIES

        fields["workspace_changed_entries"] = {
            "type": "array",
            "items": {"type": "string", "pattern": "^[a-f0-9]{32}$"},
            "maxItems": MAX_CHANGED_ENTRIES,
            "uniqueItems": True,
        }
        fields["workspace_write_scopes"] = {
            "type": "array",
            "items": {"type": "string", "enum": cast(list[JsonValue], sorted(WRITE_SCOPES))},
            "maxItems": len(WRITE_SCOPES),
            "uniqueItems": True,
        }
        # Digest-only facts for image tool results the hook saw (P3-2, issue #1013): the
        # decoded image's SHA-256 and byte count, a sniffed media type, and header dimensions.
        # No pixel crosses the wire; the domain envelope admits exactly this shape.
        dimension: dict[str, JsonValue] = {
            "maximum": 2_147_483_647,
            "minimum": 1,
            "type": "integer",
        }
        fields["observed_images"] = {
            "items": {
                "additionalProperties": False,
                "properties": {
                    "byte_count": {
                        "maximum": 9_007_199_254_740_991,
                        "minimum": 1,
                        "type": "integer",
                    },
                    "content_digest": {
                        "maxLength": 71,
                        "minLength": 71,
                        "pattern": "^sha256:[0-9a-f]{64}$",
                        "type": "string",
                    },
                    "height": dimension,
                    "media_type": {
                        "enum": [
                            "image/gif",
                            "image/jpeg",
                            "image/png",
                            "image/unknown",
                            "image/webp",
                        ],
                        "type": "string",
                    },
                    "width": dimension,
                },
                "required": ["byte_count", "content_digest", "media_type"],
                "type": "object",
            },
            "maxItems": 8,
            "minItems": 1,
            "type": "array",
        }
        # Keyed commitments to the simple commands of a compound or wrapped command and what the
        # whole outcome means for one of them (#977): planned-verification matching only. The
        # list also carries the canonical commitments (ADR-045), so its bound is the hook's.
        fields["command_segment_commitments"] = {
            "items": {
                "maxLength": 76,
                "minLength": 76,
                "pattern": _CONTROL_COMMITMENT_PATTERN,
                "type": "string",
            },
            "maxItems": MAX_COMMAND_COMMITMENTS,
            "minItems": 1,
            "type": "array",
            "uniqueItems": True,
        }
        fields["command_composition"] = {
            "enum": ["and_chain", "masked", "single"],
            "type": "string",
        }
    if entry.schema_name == "control-result":
        definitions = cast(dict[str, JsonValue], document["$defs"])
        runtime = definitions.get("observation_selection_runtime")
        if not isinstance(runtime, dict):
            raise SchemaGenerationError(
                "control_selection_runtime_schema_template_invalid",
                entries=(entry.relative_path,),
            )
        properties = runtime.get("properties")
        required = runtime.get("required")
        if (
            not isinstance(properties, dict)
            or not isinstance(required, list)
            or not isinstance(properties.get("policy_version"), dict)
            or "selected_capacity" not in properties
            or "effective_capacity" not in properties
        ):
            raise SchemaGenerationError(
                "control_selection_runtime_schema_template_invalid",
                entries=(entry.relative_path,),
            )
        token = cast(dict[str, JsonValue], properties["policy_version"])
        properties.update(
            {
                "selected_capacity": _observation_capacity_count_schema(),
                "effective_capacity": _observation_capacity_count_schema(),
                "selected_capacity_label": _observation_capacity_label_schema(),
                "effective_capacity_label": _observation_capacity_label_schema(),
                "effective_budget": {"$ref": "#/$defs/observation_effective_budget"},
            }
        )
        required.extend(["selected_capacity_label", "effective_capacity_label", "effective_budget"])
        definitions["observation_effective_budget"] = _observation_effective_budget_schema(token)
        _admit_privacy_audit_unreadable(entry, definitions)
        _admit_control_error_phase(entry, definitions)
    return _admit_privacy_policy_v1_2(document)


# The largest page ``privacy_receipts_list`` answers; a partial page cannot skip more rows than it
# reads.
_PRIVACY_RECEIPT_PAGE_MAX: Final = 100


def _admit_control_error_phase(entry: _RegistryEntry, definitions: dict[str, JsonValue]) -> None:
    """Add the bounded stage token carried by active service read failures (#954)."""

    if entry.schema_name != "control-result":
        return
    error_body = definitions.get("error_body")
    if not isinstance(error_body, dict):
        raise SchemaGenerationError(
            "control_error_schema_template_invalid", entries=(entry.relative_path,)
        )
    error_branches = error_body.get("oneOf")
    if not isinstance(error_branches, list):
        raise SchemaGenerationError(
            "control_error_schema_template_invalid", entries=(entry.relative_path,)
        )
    phase_schema: dict[str, JsonValue] = {
        "maxLength": 64,
        "pattern": "^[a-z][a-z0-9_]{0,63}$",
        "type": "string",
    }
    for error_branch in error_branches:
        if not isinstance(error_branch, dict):
            continue
        properties = error_branch.get("properties")
        if isinstance(properties, dict):
            properties["phase"] = dict(phase_schema)


def _admit_privacy_audit_unreadable(
    entry: _RegistryEntry, definitions: dict[str, JsonValue]
) -> None:
    """Let the active 2.9 result carry a partial receipt page and its store-side reason (#921).

    ``privacy receipts list`` used to fail its whole page on one stored row that could not be
    read back, and every store or decode failure reached the operator as the caller's
    ``invalid_request``. 2.9 is the active, unreleased envelope, so it gains two optional page
    fields -- ``undecodable_count`` and the structural ``undecodable_receipt_ids`` of the rows it
    skipped, present together and only on a partial page -- and one closed, non-retryable error
    code, ``privacy_audit_unreadable``. A complete page keeps its exact bytes, and every earlier
    control-result artifact stays frozen.
    """

    list_body = definitions.get("privacy_receipts_list_body")
    error_body = definitions.get("error_body")
    if not isinstance(list_body, dict) or not isinstance(error_body, dict):
        raise SchemaGenerationError(
            "control_privacy_receipt_schema_template_invalid", entries=(entry.relative_path,)
        )
    list_properties = list_body.get("properties")
    error_branches = error_body.get("oneOf")
    if (
        not isinstance(list_properties, dict)
        or "receipts" not in list_properties
        or not isinstance(error_branches, list)
    ):
        raise SchemaGenerationError(
            "control_privacy_receipt_schema_template_invalid", entries=(entry.relative_path,)
        )
    list_properties["undecodable_count"] = {
        "maxLength": 3,
        "minLength": 1,
        "pattern": "^(?:[1-9][0-9]?|100)$",
        "type": "string",
    }
    list_properties["undecodable_receipt_ids"] = {
        "items": {
            "$ref": SCHEMA_NAMESPACE + "privacy/egress-receipt-1.1.0.schema.json#/$defs/receipt_id"
        },
        "maxItems": _PRIVACY_RECEIPT_PAGE_MAX,
        "minItems": 0,
        "type": "array",
        "uniqueItems": True,
    }
    list_body["dependentRequired"] = {
        "undecodable_count": ["undecodable_receipt_ids"],
        "undecodable_receipt_ids": ["undecodable_count"],
    }
    template = next(
        (
            branch
            for branch in error_branches
            if isinstance(branch, dict)
            and cast(dict[str, JsonValue], branch.get("properties", {})).get("code")
            == {"const": "privacy_projection_blocked"}
        ),
        None,
    )
    if template is None:
        raise SchemaGenerationError(
            "control_privacy_receipt_schema_template_invalid", entries=(entry.relative_path,)
        )
    branch = cast(dict[str, JsonValue], json.loads(json.dumps(template)))
    branch_properties = cast(dict[str, JsonValue], branch["properties"])
    branch_properties["code"] = {"const": "privacy_audit_unreadable"}
    error_branches.insert(error_branches.index(template) + 1, branch)


# The local-disclosure purpose grammar owned by ``finishup.domain.privacy``.  Mirrored here rather
# than imported so the generated bytes stay a reviewable literal; the conformance suite asserts
# the two stay equal.
LOCAL_DISCLOSURE_PURPOSE_PATTERN: Final = "^[a-z][a-z0-9_-]{0,127}$"


def _admit_local_disclosure_purpose(
    entry: _RegistryEntry, definitions: dict[str, JsonValue]
) -> None:
    """Let the 2.7 wire carry the purposes local disclosure receipts actually record.

    ``local_disclosure_receipt.purpose`` referenced the privacy-policy purpose grammar, which is
    the *external egress* vocabulary and forbids underscores.  The product's own agent-projection
    purpose is ``client_result_projection`` -- a storage-CHECK-enforced value in
    ``migrations/catalog/0001.sql`` that is part of every stored receipt's canonical bytes and so
    cannot be renamed.  Ordinary local receipts therefore failed ``_validated_wire`` and broke
    ``privacy receipts list``/``get`` (issue #732).

    The fix stays on the schema side and stays local: 2.7 is the active, unreleased envelope, so
    it gains a ``local_disclosure_purpose`` definition mirroring the domain grammar that produces
    these values.  ``privacy/egress-receipt-1.0.0`` is untouched, so network egress purposes keep
    the hyphen-only external vocabulary this codebase already requires of anything crossing the
    privacy-policy boundary.
    """

    local_receipt = definitions.get("local_disclosure_receipt")
    if not isinstance(local_receipt, dict):
        raise SchemaGenerationError(
            "control_local_receipt_schema_template_invalid", entries=(entry.relative_path,)
        )
    local_properties = local_receipt.get("properties")
    if not isinstance(local_properties, dict) or "purpose" not in local_properties:
        raise SchemaGenerationError(
            "control_local_receipt_schema_template_invalid", entries=(entry.relative_path,)
        )
    definitions["local_disclosure_purpose"] = {
        "maxLength": 128,
        "minLength": 1,
        "pattern": LOCAL_DISCLOSURE_PURPOSE_PATTERN,
        "type": "string",
    }
    local_properties["purpose"] = {"$ref": "#/$defs/local_disclosure_purpose"}


def _control_v2_7_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Derive the 0.3 project-control contract from the frozen main 2.6 wire.

    Main's 2.6 control files are a released observation/selection baseline and remain frozen.
    The 0.3 project and coordination additions are therefore an append-only 2.7 contract derived
    from those exact bytes, with the current operation-result references retargeted as usual.
    The request and result envelopes derive from the released ``2.6.1`` patch (0.2.3): it carries
    the selected-observation route fields, protected-read reference, subject-state digest, the
    routine-read-summary branch, and the local disclosure purpose grammar that the 0.2 line
    already ships. The hello envelopes have no ``2.6.1`` and derive from ``2.6.0``.
    """

    template_version = (
        "2.6.1" if entry.schema_name in {"control-request", "control-result"} else "2.6.0"
    )
    source = (
        Path(__file__).resolve().parent.parent
        / "schemas"
        / entry.relative_path.replace("2.7.0", template_version)
    )
    try:
        document = cast(dict[str, JsonValue], json.loads(source.read_bytes()))
    except (OSError, TypeError, json.JSONDecodeError) as exc:
        raise SchemaGenerationError(
            "control_schema_template_invalid", entries=(entry.relative_path,)
        ) from exc
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path

    operation_ref_replacements = {
        SCHEMA_NAMESPACE + "operations/start-request-1.0.0.schema.json": SCHEMA_NAMESPACE
        + "operations/start-request-1.1.0.schema.json",
        SCHEMA_NAMESPACE + "operations/start-result-1.0.0.schema.json": SCHEMA_NAMESPACE
        + "operations/start-result-1.1.0.schema.json",
        SCHEMA_NAMESPACE + "operations/publish-work-request-1.1.0.schema.json": SCHEMA_NAMESPACE
        + "operations/publish-work-request-1.2.0.schema.json",
        SCHEMA_NAMESPACE + "operations/check-request-1.0.0.schema.json": SCHEMA_NAMESPACE
        + "operations/check-request-1.1.0.schema.json",
        SCHEMA_NAMESPACE + "operations/check-result-1.2.0.schema.json": SCHEMA_NAMESPACE
        + "operations/check-result-1.3.0.schema.json",
        SCHEMA_NAMESPACE + "operations/status-request-1.1.0.schema.json": SCHEMA_NAMESPACE
        + "operations/status-request-1.2.0.schema.json",
        SCHEMA_NAMESPACE + "operations/status-result-1.3.0.schema.json": SCHEMA_NAMESPACE
        + "operations/status-result-1.4.0.schema.json",
        SCHEMA_NAMESPACE + "operations/receipt-result-1.2.0.schema.json": SCHEMA_NAMESPACE
        + "operations/receipt-result-1.3.0.schema.json",
    }

    def retarget(node: JsonValue) -> None:
        if isinstance(node, dict):
            for key, value in tuple(node.items()):
                if type(value) is str:
                    node[key] = operation_ref_replacements.get(value, value)
                else:
                    retarget(value)
        elif isinstance(node, list):
            for value in node:
                retarget(value)

    retarget(document)
    if entry.schema_name == "control-hello":
        return document
    if entry.schema_name == "control-hello-result":
        properties = cast(dict[str, JsonValue], document["properties"])
        allowed = cast(dict[str, JsonValue], properties["allowed_methods"])
        enum_values = cast(list[JsonValue], allowed["enum"])
        item_values = cast(dict[str, JsonValue], allowed["items"])
        item_enum = cast(list[JsonValue], item_values["enum"])
        for values in (enum_values[1], item_enum):
            methods = cast(list[JsonValue], values)
            if "project" not in methods:
                methods.append("project")
            methods.sort(key=lambda value: str(value).encode("ascii"))
        allowed["maxItems"] = 32
        return document
    definitions = cast(dict[str, JsonValue], document["$defs"])
    branches = cast(list[JsonValue], document["oneOf"])
    if entry.schema_name == "control-request":
        # Native Claude/Cursor ingress adds the reviewed pairing contract to the structural
        # observation payload.  These fields are intentionally current 2.7-only: the 2.6
        # document is frozen, while cloning it here must still track every field the domain
        # serializer can emit (including Cursor's generation identity).
        observation_envelope = _individual_observation_envelope(definitions)
        envelope_properties = cast(dict[str, JsonValue], observation_envelope["properties"])
        structural_payload = cast(dict[str, JsonValue], envelope_properties["structural_payload"])
        structural_properties = cast(dict[str, JsonValue], structural_payload["properties"])
        structural_properties.update(
            {
                "correlation_kind": {
                    "enum": ["generation_id", "none", "tool_call_id"],
                    "type": "string",
                },
                "generation_id": {
                    "maxLength": 128,
                    "minLength": 1,
                    "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$",
                    "type": "string",
                },
                "pairing_mode": {
                    "enum": ["paired", "post_only"],
                    "type": "string",
                },
                "selection_authority_generation": {
                    "maxLength": 71,
                    "minLength": 71,
                    "pattern": _CONTROL_DIGEST_PATTERN,
                    "type": "string",
                },
                "selection_session_id": _control_id_schema("session_id"),
                "selection_task_id": _control_id_schema("task_id"),
                "selection_writer_id": _control_id_schema("writer_id"),
            }
        )
    if entry.schema_name == "control-result":
        _admit_local_disclosure_purpose(entry, definitions)
        # Project lifecycle refusals are bounded application reasons, not transport failures. 2.7
        # is the first control envelope that carries the CLI-only project method, so extend only
        # this unreleased schema's generic error branch; every older control-result artifact stays
        # frozen. Keep the finite vocabulary explicit here so a caller cannot smuggle arbitrary
        # project text into a wire error code.
        coordination_reasons = (
            # Main's shared control vocabulary uses this bounded reason for policy-layer
            # request rejection.  It is absent from the frozen 2.6 transport enum, so the
            # active 2.7 envelope must add it alongside the project coordination reasons.
            "invalid_request",
            "coordination_invalid",
            "project_not_found",
            "project_dissolved",
            "implicit_project_requires_opt_out",
            "general_project_membership_conflict",
            "project_member_not_found",
            "selector_conflict",
            "coordination_consent_required",
            "coordination_source_policy_denied",
            "coordination_grant_required",
            "coordination_generation_revoked",
            "coordination_generation_mismatch",
            "cross_repository_lineage_requires_grant",
            "project_member_already_unbound",
        )
        error_body = definitions.get("error_body")
        if not isinstance(error_body, dict):
            raise SchemaGenerationError(
                "control_error_schema_template_invalid", entries=(entry.relative_path,)
            )
        error_branches = error_body.get("oneOf")
        if not isinstance(error_branches, list):
            raise SchemaGenerationError(
                "control_error_schema_template_invalid", entries=(entry.relative_path,)
            )
        for error_branch in error_branches:
            if not isinstance(error_branch, dict):
                continue
            properties = error_branch.get("properties")
            if not isinstance(properties, dict):
                continue
            code_schema = properties.get("code")
            if not isinstance(code_schema, dict):
                continue
            enum_values = code_schema.get("enum")
            if not isinstance(enum_values, list):
                continue
            enum_values.extend(
                reason for reason in coordination_reasons if reason not in enum_values
            )
            enum_values.sort(key=lambda value: str(value).encode("ascii"))
            break
        else:
            raise SchemaGenerationError(
                "control_error_schema_template_invalid", entries=(entry.relative_path,)
            )
    if entry.schema_name == "control-request":
        definitions["project_body"] = _control_project_request_schema()
        template = next(
            cast(dict[str, JsonValue], branch)
            for branch in branches
            if isinstance(branch, dict)
            and cast(dict[str, JsonValue], branch.get("properties", {})).get("method")
            == {"const": "review"}
        )
        project_branch = cast(dict[str, JsonValue], json.loads(json.dumps(template)))
        project_properties = cast(dict[str, JsonValue], project_branch["properties"])
        project_properties["body"] = {"$ref": "#/$defs/project_body"}
        project_properties["method"] = {"const": "project"}
        branches.append(project_branch)
        branches.sort(
            key=lambda branch: str(
                cast(dict[str, JsonValue], cast(dict[str, JsonValue], branch).get("properties", {}))
                .get("method", {})
                .get("const", "")
            ).encode("ascii")
        )
        return document
    definitions.update(_control_project_result_schema()["$defs"])
    result_defs = _control_project_result_schema()
    # The result helper's top-level oneOf is referenced from the project success branch below;
    # its local definitions are merged into the existing envelope definitions.
    template_error = next(
        cast(dict[str, JsonValue], branch)
        for branch in branches
        if isinstance(branch, dict)
        and cast(dict[str, JsonValue], branch.get("properties", {})).get("method")
        == {"const": "review"}
        and cast(dict[str, JsonValue], branch.get("properties", {})).get("outcome")
        == {"const": "error"}
    )
    template_ok = next(
        cast(dict[str, JsonValue], branch)
        for branch in branches
        if isinstance(branch, dict)
        and cast(dict[str, JsonValue], branch.get("properties", {})).get("method")
        == {"const": "review"}
        and cast(dict[str, JsonValue], branch.get("properties", {})).get("outcome")
        == {"const": "ok"}
    )
    error_branch = cast(dict[str, JsonValue], json.loads(json.dumps(template_error)))
    ok_branch = cast(dict[str, JsonValue], json.loads(json.dumps(template_ok)))
    cast(dict[str, JsonValue], error_branch["properties"])["method"] = {"const": "project"}
    cast(dict[str, JsonValue], ok_branch["properties"])["method"] = {"const": "project"}
    cast(dict[str, JsonValue], ok_branch["properties"])["body"] = {"oneOf": result_defs["oneOf"]}
    branches.extend((error_branch, ok_branch))
    branches.sort(
        key=lambda branch: (
            str(
                cast(dict[str, JsonValue], cast(dict[str, JsonValue], branch).get("properties", {}))
                .get("method", {})
                .get("const", "")
            ).encode("ascii"),
            str(
                cast(dict[str, JsonValue], cast(dict[str, JsonValue], branch).get("properties", {}))
                .get("outcome", {})
                .get("const", "")
            ).encode("ascii"),
        )
    )
    return document


def _publish_work_result_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Preserve the reviewed publish result rather than replacing it with model introspection."""

    source = Path(__file__).resolve().parent.parent / "schemas" / entry.relative_path
    try:
        return cast(dict[str, JsonValue], json.loads(source.read_bytes()))
    except (OSError, TypeError, json.JSONDecodeError) as exc:
        raise SchemaGenerationError(
            "publish_work_result_schema_template_invalid", entries=(entry.relative_path,)
        ) from exc


def _publish_work_result_v1_1_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Report the current built-in pack versions in the publish result's version slice.

    The released 1.0.0 result pins both packs at ``0.1.0``; an older service keeps it.
    """

    document = _load_versioned_template(entry, "operations/publish-work-result-1.0.0.schema.json")
    _admit_recorded_policy_identities(document)
    _add_publish_blocker_notices(document)
    _add_publish_action_notices(document)
    _add_publish_server_filled(document)
    return document


def _server_filled_schema() -> dict[str, JsonValue]:
    """The ``server_filled`` record: which values the service supplied (issue #1084)."""

    from finishup.protocol.publish_boilerplate import (
        FILLABLE_DRAFT_FIELDS,
        FILLABLE_REQUEST_FIELDS,
    )

    return {
        "additionalProperties": False,
        "properties": {
            "drafts": {
                "items": {
                    "additionalProperties": False,
                    "properties": {
                        "fields": {
                            "items": {"enum": list(FILLABLE_DRAFT_FIELDS), "type": "string"},
                            "maxItems": len(FILLABLE_DRAFT_FIELDS),
                            "minItems": 1,
                            "type": "array",
                            "uniqueItems": True,
                        },
                        "indexes": {
                            "items": {"$ref": "#/$defs/canonical_uint"},
                            "maxItems": 100,
                            "minItems": 1,
                            "type": "array",
                            "uniqueItems": True,
                        },
                    },
                    "required": ["fields", "indexes"],
                    "type": "object",
                },
                # One group per distinct filled-field set (at most 2^5 - 1 of them).
                "maxItems": 31,
                "type": "array",
            },
            "request": {
                "items": {"enum": list(FILLABLE_REQUEST_FIELDS), "type": "string"},
                "maxItems": len(FILLABLE_REQUEST_FIELDS),
                "type": "array",
                "uniqueItems": True,
            },
        },
        "required": ["request", "drafts"],
        "type": "object",
    }


def _add_publish_server_filled(document: dict[str, JsonValue]) -> None:
    """Optional record of the values the service filled (issue #1084).

    Present only when the caller omitted at least one fillable value, so a request that sends every
    field still receives its earlier result shape.
    """

    definitions = cast(dict[str, JsonValue], document["$defs"])
    definitions["server_filled"] = _server_filled_schema()
    # The reduced success keeps the provenance of the operation it reports (review R1).
    for branch in ("success", "accepted_projection_unavailable", "dry_run"):
        properties = cast(
            dict[str, JsonValue], cast(dict[str, JsonValue], definitions[branch])["properties"]
        )
        properties["server_filled"] = {"$ref": "#/$defs/server_filled"}


def _add_publish_action_notices(document: dict[str, JsonValue]) -> None:
    """Optional fixed publish-time notices for an action no result names (tb4n5 follow-up)."""

    from finishup.protocol.models import PUBLISH_ACTION_NOTICE_TEXTS

    definitions = cast(dict[str, JsonValue], document["$defs"])
    definitions["action_id"] = {
        "pattern": ("^act_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"),
        "type": "string",
    }
    definitions["action_notice"] = {
        "additionalProperties": False,
        "oneOf": [
            {
                "properties": {
                    "notice": {"const": notice},
                    "text": {"const": text},
                }
            }
            for notice, text in sorted(PUBLISH_ACTION_NOTICE_TEXTS.items())
        ],
        "properties": {
            "action_id": {"$ref": "#/$defs/action_id"},
            "notice": {"enum": sorted(PUBLISH_ACTION_NOTICE_TEXTS), "type": "string"},
            "text": {"type": "string"},
        },
        "required": ["action_id", "notice", "text"],
        "type": "object",
    }
    for branch in ("success", "dry_run"):
        properties = cast(
            dict[str, JsonValue], cast(dict[str, JsonValue], definitions[branch])["properties"]
        )
        properties["action_notices"] = {
            "items": {"$ref": "#/$defs/action_notice"},
            # One row per unpaired action: the batch bound (MAX_EVENTS_PER_BATCH), never a cut.
            "maxItems": 100,
            "minItems": 1,
            "type": "array",
        }


def _add_publish_blocker_notices(document: dict[str, JsonValue]) -> None:
    """Optional fixed publish-time notices for a ``yoetz-blocker`` line (issue #985)."""

    from finishup.protocol.models import PUBLISH_BLOCKER_NOTICE_TEXTS

    definitions = cast(dict[str, JsonValue], document["$defs"])
    definitions["obligation_id"] = {
        "pattern": ("^obl_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"),
        "type": "string",
    }
    definitions["blocker_notice"] = {
        "additionalProperties": False,
        "oneOf": [
            {
                "properties": {
                    "notice": {"const": notice},
                    "text": {"const": text},
                }
            }
            for notice, text in sorted(PUBLISH_BLOCKER_NOTICE_TEXTS.items())
        ],
        "properties": {
            "blocker_kind": {
                "enum": ["authority", "consent", "credential", "dependency_unavailable"],
                "type": "string",
            },
            "notice": {"enum": sorted(PUBLISH_BLOCKER_NOTICE_TEXTS), "type": "string"},
            "obligation_id": {"$ref": "#/$defs/obligation_id"},
            "text": {"type": "string"},
        },
        "required": ["blocker_kind", "notice", "obligation_id", "text"],
        "type": "object",
    }
    for branch in ("success", "dry_run"):
        properties = cast(
            dict[str, JsonValue], cast(dict[str, JsonValue], definitions[branch])["properties"]
        )
        properties["blocker_notices"] = {
            "items": {"$ref": "#/$defs/blocker_notice"},
            "maxItems": 64,
            "minItems": 1,
            "type": "array",
        }


def _status_result_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Extend the reviewed status result with model-owned completion and disposition leaves."""

    source = (
        Path(__file__).resolve().parent.parent
        / "schemas/operations/status-result-1.0.0.schema.json"
    )
    try:
        document = cast(dict[str, JsonValue], json.loads(source.read_bytes()))
        definitions = cast(dict[str, JsonValue], document["$defs"])
        compact = cast(dict[str, JsonValue], definitions["compact_item"])
        compact_properties = cast(dict[str, JsonValue], compact["properties"])
        compact_required = cast(list[JsonValue], compact["required"])
        history = cast(dict[str, JsonValue], definitions["history_item"])
        history_properties = cast(dict[str, JsonValue], history["properties"])
        history_required = cast(list[JsonValue], history["required"])
        finding_item = cast(dict[str, JsonValue], definitions["finding_item"])
        finding_properties = cast(dict[str, JsonValue], finding_item["properties"])
        finding_rules_value = finding_item.setdefault("allOf", [])
        if not isinstance(finding_rules_value, list):
            raise TypeError("finding_item allOf must be an array")
        finding_rules = cast(list[JsonValue], finding_rules_value)
        readiness = cast(dict[str, JsonValue], definitions["closure_readiness"])
        readiness_properties = cast(dict[str, JsonValue], readiness["properties"])
        readiness_required = cast(list[JsonValue], readiness["required"])
        blocking = cast(dict[str, JsonValue], readiness_properties["blocking_conditions"])
        blocking_items = cast(dict[str, JsonValue], blocking["items"])
        blocker_values = cast(list[JsonValue], blocking_items["enum"])
    except (KeyError, OSError, TypeError, json.JSONDecodeError) as exc:
        raise SchemaGenerationError(
            "status_result_schema_template_invalid", entries=(entry.relative_path,)
        ) from exc

    definitions["no_obligations_reason"] = {
        "enum": [
            "no_material_change",
            "single_atomic_change",
            "exploratory_scope_unknown",
        ],
        "type": "string",
    }
    finding_properties["disposition"] = {
        "enum": [
            "acknowledged",
            "none",
            "provenance_disputed",
            "rejected",
            "waived",
        ],
        "type": "string",
    }
    if not any(
        isinstance(rule, dict)
        and isinstance(rule.get("if"), dict)
        and isinstance(cast(dict[str, JsonValue], rule["if"]).get("properties"), dict)
        and cast(
            dict[str, JsonValue],
            cast(dict[str, JsonValue], rule["if"])["properties"],
        ).get("disposition")
        == {"const": "provenance_disputed"}
        for rule in finding_rules
    ):
        finding_rules.append(
            {
                "if": {
                    "properties": {"disposition": {"const": "provenance_disputed"}},
                    "required": ["disposition"],
                },
                "then": {
                    "properties": {
                        "reason": {"not": {"type": "null"}},
                        "resolved": {"const": False},
                        "waiver_expiry": {"type": "null"},
                        "waiver_scope": {"type": "null"},
                    }
                },
            }
        )
    history_properties["occurred_at_consistency"] = {
        "description": (
            "Exact comparison of caller-asserted occurred_at with service accepted_at. Caller "
            "time through five seconds ahead is within_forward_skew_allowance; larger forward "
            "drift is ahead_of_forward_skew_allowance. This does not verify caller time or "
            "affect ingestion-sequence ordering."
        ),
        "enum": [
            "within_forward_skew_allowance",
            "ahead_of_forward_skew_allowance",
        ],
        "type": "string",
    }
    if "occurred_at_consistency" not in history_required:
        accepted_at_index = history_required.index("accepted_at")
        history_required.insert(accepted_at_index + 1, "occurred_at_consistency")
    nullable_count: dict[str, JsonValue] = {
        "oneOf": [
            {"$ref": "#/$defs/canonical_uint"},
            {"type": "null"},
        ]
    }
    nullable_reason: dict[str, JsonValue] = {
        "oneOf": [
            {"$ref": "#/$defs/no_obligations_reason"},
            {"type": "null"},
        ]
    }
    compact_properties["declared_obligation_count"] = nullable_count
    compact_properties["no_obligations_reason"] = nullable_reason
    compact_properties["open_obligation_count"] = nullable_count
    legacy_unanswered_count = compact_properties.pop("unresolved_finding_count", None)
    if legacy_unanswered_count is not None:
        compact_properties["unanswered_finding_count"] = legacy_unanswered_count
    compact_properties["receipt_blocking_finding_count"] = {"$ref": "#/$defs/canonical_uint"}
    legacy_unanswered_items = compact_properties.pop("unresolved_findings", None)
    if legacy_unanswered_items is not None:
        compact_properties["unanswered_findings"] = legacy_unanswered_items
    if "unresolved_finding_count" in compact_required:
        compact_required[compact_required.index("unresolved_finding_count")] = (
            "unanswered_finding_count"
        )
    if "receipt_blocking_finding_count" not in compact_required:
        unanswered_index = compact_required.index("unanswered_finding_count")
        compact_required.insert(unanswered_index + 1, "receipt_blocking_finding_count")
    if "unresolved_findings" in compact_required:
        compact_required[compact_required.index("unresolved_findings")] = "unanswered_findings"
    readiness_properties["declared_obligation_count"] = nullable_count
    readiness_properties["no_obligations_reason"] = nullable_reason
    legacy_readiness_count = readiness_properties.pop("unresolved_finding_count", None)
    if legacy_readiness_count is not None:
        readiness_properties["unanswered_finding_count"] = legacy_readiness_count
    readiness_properties["receipt_blocking_finding_count"] = nullable_count
    if "unresolved_finding_count" in readiness_required:
        readiness_required[readiness_required.index("unresolved_finding_count")] = (
            "unanswered_finding_count"
        )
    if "receipt_blocking_finding_count" not in readiness_required:
        unanswered_index = readiness_required.index("unanswered_finding_count")
        readiness_required.insert(unanswered_index + 1, "receipt_blocking_finding_count")
    for required, names in (
        (compact_required, ("declared_obligation_count", "no_obligations_reason")),
        (readiness_required, ("declared_obligation_count", "no_obligations_reason")),
    ):
        for name in names:
            if name not in required:
                required.append(name)
    if "findings_unresolved" in blocker_values:
        blocker_values.remove("findings_unresolved")
    for blocker in (
        "findings_unanswered",
        "receipt_findings_unresolved",
        "no_obligations_declared",
    ):
        if blocker not in blocker_values:
            blocker_values.append(blocker)
    if entry.schema_version == "1.1.0":
        _extend_status_result_v11(document)
        document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
        document["title"] = "Yoetz status result 1.1.0"
    return document


def _extend_status_result_v11(document: dict[str, JsonValue]) -> None:
    """Add actionable result and requested-item projections to the frozen v1.0 shape."""

    definitions = cast(dict[str, JsonValue], document["$defs"])
    obligation = cast(dict[str, JsonValue], definitions["obligation_item"])
    obligation_properties = cast(dict[str, JsonValue], obligation["properties"])
    success = cast(dict[str, JsonValue], definitions["success"])
    success_properties = cast(dict[str, JsonValue], success["properties"])
    success_view = cast(dict[str, JsonValue], success_properties["view"])
    success_pages = cast(dict[str, JsonValue], success_properties["page"])
    success_page_refs = cast(list[JsonValue], success_pages["anyOf"])
    success_view_rules = cast(list[JsonValue], success["allOf"])

    definitions["action_id"] = {
        "pattern": "^act_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        "type": "string",
    }
    definitions["result_id"] = {
        "pattern": "^res_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        "type": "string",
    }
    definitions["requested_item_text"] = {"maxLength": 1024, "type": "string"}
    definitions["status_requested_item"] = {
        "additionalProperties": False,
        "properties": {
            "item_kind": {
                "enum": ["url", "file", "command", "change", "source"],
                "type": "string",
            },
            "value": {
                "oneOf": [
                    {"$ref": "#/$defs/requested_item_text"},
                    {"$ref": "#/$defs/obligation_omission"},
                ]
            },
        },
        "required": ["item_kind", "value"],
        "type": "object",
    }
    requested_item_list: dict[str, JsonValue] = {
        "items": {"$ref": "#/$defs/status_requested_item"},
        "maxItems": 64,
        "type": "array",
    }
    obligation_properties["requested_items"] = requested_item_list
    obligation_properties["unattempted_items"] = requested_item_list
    obligation_properties["command_attempts"] = {
        "type": "array",
        "maxItems": 64,
        "items": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "requested_item_index",
                "relation",
                "asserted_action_ids",
                "observed_event_ids",
            ],
            "properties": {
                "requested_item_index": {
                    "type": "string",
                    "pattern": "^(?:[0-9]|[1-5][0-9]|6[0-3])$",
                },
                "relation": {
                    "enum": ["matching_observed_attempt", "asserted_observed_mismatch", "unknown"]
                },
                "asserted_action_ids": {
                    "type": "array",
                    "maxItems": 64,
                    "uniqueItems": True,
                    "items": {"$ref": "#/$defs/action_id"},
                },
                "observed_event_ids": {
                    "type": "array",
                    "maxItems": 64,
                    "uniqueItems": True,
                    "items": {"$ref": "#/$defs/event_id"},
                },
            },
        },
    }
    definitions["result_item"] = {
        "additionalProperties": False,
        "properties": {
            "action_id": {"oneOf": [{"$ref": "#/$defs/action_id"}, {"type": "null"}]},
            "evidence_refs": {
                "items": {"$ref": "#/$defs/evidence_id"},
                "maxItems": 64,
                "type": "array",
                "uniqueItems": True,
            },
            "outcome": {
                "oneOf": [
                    {
                        "enum": ["success", "failure", "partial", "unknown"],
                        "type": "string",
                    },
                    {"type": "null"},
                ]
            },
            "payload_available": {"type": "boolean"},
            "result_id": {"$ref": "#/$defs/result_id"},
            "source_event_id": {"$ref": "#/$defs/event_id"},
        },
        "required": [
            "result_id",
            "source_event_id",
            "payload_available",
            "outcome",
            "action_id",
            "evidence_refs",
        ],
        "type": "object",
    }
    definitions["results_page"] = {
        "additionalProperties": False,
        "properties": {
            "items": {
                "items": {"$ref": "#/$defs/result_item"},
                "maxItems": 100,
                "type": "array",
            },
            "next_cursor": {"$ref": "#/$defs/nullable_cursor"},
        },
        "required": ["items", "next_cursor"],
        "type": "object",
    }
    definitions["view_results"] = {
        "if": {"properties": {"view": {"const": "results"}}, "required": ["view"]},
        "then": {"properties": {"page": {"$ref": "#/$defs/results_page"}}},
    }
    view_values = cast(list[JsonValue], success_view["enum"])
    view_values.insert(view_values.index("versions"), "results")
    success_page_refs.append({"$ref": "#/$defs/results_page"})
    success_view_rules.append({"$ref": "#/$defs/view_results"})


def _receipt_document_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Extend the reviewed receipt document with the model-owned response disposition."""

    source = Path(__file__).resolve().parent.parent / "schemas" / entry.relative_path
    try:
        document = cast(dict[str, JsonValue], json.loads(source.read_bytes()))
        definitions = cast(dict[str, JsonValue], document["$defs"])
        response = cast(dict[str, JsonValue], definitions["receipt_response"])
        response_properties = cast(dict[str, JsonValue], response["properties"])
        disposition = cast(dict[str, JsonValue], response_properties["disposition"])
        rules = cast(list[JsonValue], response["allOf"])
    except (KeyError, OSError, TypeError, json.JSONDecodeError) as exc:
        raise SchemaGenerationError(
            "receipt_document_schema_template_invalid", entries=(entry.relative_path,)
        ) from exc

    disposition["enum"] = ["acknowledged", "provenance_disputed", "rejected", "waived"]
    has_provenance_rule = False
    for rule_value in rules:
        if not isinstance(rule_value, dict):
            continue
        condition = rule_value.get("if")
        if not isinstance(condition, dict):
            continue
        properties = condition.get("properties")
        if not isinstance(properties, dict):
            continue
        disposition_condition = properties.get("disposition")
        if isinstance(disposition_condition, dict) and disposition_condition.get("const") == (
            "provenance_disputed"
        ):
            has_provenance_rule = True
            break
    if not has_provenance_rule:
        rules.insert(
            1,
            {
                "if": {
                    "properties": {"disposition": {"const": "provenance_disputed"}},
                    "required": ["disposition"],
                },
                "then": {
                    "not": {
                        "anyOf": [
                            {"required": ["waiver_scope"]},
                            {"required": ["waiver_expiry"]},
                        ]
                    },
                    "required": ["reason"],
                },
            },
        )
    return document


def _response_recorded_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Extend the reviewed response event with the model-owned response disposition."""

    source = Path(__file__).resolve().parent.parent / "schemas" / entry.relative_path
    try:
        document = cast(dict[str, JsonValue], json.loads(source.read_bytes()))
        properties = cast(dict[str, JsonValue], document["properties"])
        disposition = cast(dict[str, JsonValue], properties["disposition"])
        rules = cast(list[JsonValue], document["oneOf"])
    except (KeyError, OSError, TypeError, json.JSONDecodeError) as exc:
        raise SchemaGenerationError(
            "response_recorded_schema_template_invalid", entries=(entry.relative_path,)
        ) from exc

    disposition["enum"] = ["acknowledged", "provenance_disputed", "rejected", "waived"]
    if not any(
        isinstance(rule, dict)
        and isinstance(rule.get("properties"), dict)
        and cast(dict[str, JsonValue], rule["properties"]).get("disposition")
        == {"const": "provenance_disputed"}
        for rule in rules
    ):
        rules.insert(
            1,
            {
                "not": {
                    "anyOf": [
                        {"required": ["waiver_scope"]},
                        {"required": ["waiver_expiry"]},
                    ]
                },
                "properties": {"disposition": {"const": "provenance_disputed"}},
                "required": ["reason"],
            },
        )
    return document


def _insert_provenance_dispute_condition(rules: list[JsonValue]) -> None:
    """Add the shared reason-required, waiver-forbidden branch once."""

    for rule_value in rules:
        if not isinstance(rule_value, dict):
            continue
        condition = rule_value.get("if")
        if not isinstance(condition, dict):
            continue
        properties = condition.get("properties")
        if not isinstance(properties, dict):
            continue
        disposition = properties.get("disposition")
        if isinstance(disposition, dict) and disposition.get("const") == "provenance_disputed":
            return
    rules.insert(
        1,
        {
            "if": {
                "properties": {"disposition": {"const": "provenance_disputed"}},
                "required": ["disposition"],
            },
            "then": {
                "not": {
                    "anyOf": [
                        {"required": ["waiver_scope"]},
                        {"required": ["waiver_expiry"]},
                    ]
                },
                "required": ["reason"],
            },
        },
    )


def _respond_request_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Extend the reviewed respond request with the model-owned response disposition."""

    source = Path(__file__).resolve().parent.parent / "schemas" / entry.relative_path
    try:
        document = cast(dict[str, JsonValue], json.loads(source.read_bytes()))
        properties = cast(dict[str, JsonValue], document["properties"])
        disposition = cast(dict[str, JsonValue], properties["disposition"])
        rules = cast(list[JsonValue], document["allOf"])
    except (KeyError, OSError, TypeError, json.JSONDecodeError) as exc:
        raise SchemaGenerationError(
            "respond_request_schema_template_invalid", entries=(entry.relative_path,)
        ) from exc
    disposition["enum"] = ["acknowledged", "provenance_disputed", "rejected", "waived"]
    _insert_provenance_dispute_condition(rules)
    return document


def _respond_result_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Extend the reviewed respond result with the model-owned response disposition."""

    source = Path(__file__).resolve().parent.parent / "schemas" / entry.relative_path
    try:
        document = cast(dict[str, JsonValue], json.loads(source.read_bytes()))
        definitions = cast(dict[str, JsonValue], document["$defs"])
        response = cast(dict[str, JsonValue], definitions["response"])
        properties = cast(dict[str, JsonValue], response["properties"])
        disposition = cast(dict[str, JsonValue], properties["disposition"])
        rules = cast(list[JsonValue], response["allOf"])
    except (KeyError, OSError, TypeError, json.JSONDecodeError) as exc:
        raise SchemaGenerationError(
            "respond_result_schema_template_invalid", entries=(entry.relative_path,)
        ) from exc
    disposition["enum"] = ["acknowledged", "provenance_disputed", "rejected", "waived"]
    _insert_provenance_dispute_condition(rules)
    return document


_ACKNOWLEDGED_NOT_DONE: Final = "acknowledged_not_done"


def _no_waiver_fields() -> dict[str, JsonValue]:
    return {"not": {"anyOf": [{"required": ["waiver_scope"]}, {"required": ["waiver_expiry"]}]}}


_SELF_VERIFIED: Final = "self_verified"
_REOPENED: Final = "reopened"


def _admit_terminal_dispositions(disposition: dict[str, JsonValue]) -> None:
    """Add the terminal not-done (#905), self-verified (#984) and reopened (#1030) dispositions."""

    values = cast(list[JsonValue], disposition["enum"])
    for value in (_ACKNOWLEDGED_NOT_DONE, _SELF_VERIFIED, _REOPENED):
        if value not in values:
            values.append(value)
    values.sort(key=lambda item: str(item).encode("ascii"))


_DUPLICATE_OF: Final = "duplicate_of"
_DUPLICATE_OF_FIELD: Final = "duplicate_of_finding_id"


def _admit_duplicate_of(
    properties: dict[str, JsonValue],
    rules: list[JsonValue],
    *,
    one_of: bool = False,
    link_field: bool = True,
) -> dict[str, JsonValue] | None:
    """Admit the ``duplicate_of`` disposition (issue #996) on one response-shaped object.

    It accepts no waiver fields; with ``link_field`` it requires ``duplicate_of_finding_id`` (the
    same pattern as ``finding_id``) and returns the rule that keeps that field off every other
    disposition, for the caller to place on the object.
    """

    disposition = cast(dict[str, JsonValue], properties["disposition"])
    values = cast(list[JsonValue], disposition["enum"])
    if _DUPLICATE_OF not in values:
        values.append(_DUPLICATE_OF)
    values.sort(key=lambda item: str(item).encode("ascii"))
    required: list[JsonValue] = [_DUPLICATE_OF_FIELD] if link_field else []
    if one_of:
        rule: dict[str, JsonValue] = {
            **_no_waiver_fields(),
            "properties": {"disposition": {"const": _DUPLICATE_OF}},
        }
        if required:
            rule["required"] = required
    else:
        then: dict[str, JsonValue] = dict(_no_waiver_fields())
        if required:
            then["required"] = required
        rule = {
            "if": {
                "properties": {"disposition": {"const": _DUPLICATE_OF}},
                "required": ["disposition"],
            },
            "then": then,
        }
    # Disposition order: right after ``acknowledged_not_done`` (or ``acknowledged``).
    index = 0
    for position, existing in enumerate(rules):
        current = cast(dict[str, JsonValue], existing)
        guard = cast(dict[str, JsonValue], current.get("if", current))
        guard_properties = cast(dict[str, JsonValue], guard.get("properties", {}))
        const = cast(dict[str, JsonValue], guard_properties.get("disposition", {})).get("const")
        if const in {"acknowledged", _ACKNOWLEDGED_NOT_DONE}:
            index = position + 1
    rules.insert(index, rule)
    if not link_field:
        return None
    properties[_DUPLICATE_OF_FIELD] = json.loads(json.dumps(properties["finding_id"]))
    return {
        "if": {"required": [_DUPLICATE_OF_FIELD]},
        "then": {
            "properties": {"disposition": {"const": _DUPLICATE_OF}},
            "required": ["disposition"],
        },
    }


def _insert_before_waived(rules: list[JsonValue], rule: dict[str, JsonValue]) -> None:
    """Insert one per-disposition rule in disposition order, before the ``waived`` rule."""

    for index, existing in enumerate(rules):
        current = cast(dict[str, JsonValue], existing)
        guard = cast(dict[str, JsonValue], current.get("if", current))
        properties = cast(dict[str, JsonValue], guard.get("properties", {}))
        disposition = cast(dict[str, JsonValue], properties.get("disposition", {}))
        if disposition.get("const") == "waived":
            rules.insert(index, rule)
            return
    rules.append(rule)


def _self_verified_condition(evidence_field: str = "evidence_refs") -> dict[str, JsonValue]:
    """``self_verified`` needs a reason and at least one evidence reference, never a waiver."""

    return {
        "if": {
            "properties": {"disposition": {"const": _SELF_VERIFIED}},
            "required": ["disposition"],
        },
        "then": {
            **_no_waiver_fields(),
            "properties": {evidence_field: {"minItems": 1}},
            "required": ["reason", evidence_field],
        },
    }


def _acknowledged_not_done_condition() -> dict[str, JsonValue]:
    """``acknowledged_not_done`` requires a reason and accepts no waiver fields."""

    return {
        "if": {
            "properties": {"disposition": {"const": _ACKNOWLEDGED_NOT_DONE}},
            "required": ["disposition"],
        },
        "then": {**_no_waiver_fields(), "required": ["reason"]},
    }


def _reopened_condition() -> dict[str, JsonValue]:
    """``reopened`` (tb4n3 RC-7, #1030) takes a not-done answer back: a reason, no waiver fields."""

    return {
        "if": {
            "properties": {"disposition": {"const": _REOPENED}},
            "required": ["disposition"],
        },
        "then": {**_no_waiver_fields(), "required": ["reason"]},
    }


def _response_recorded_v1_1_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Admit the terminal ``acknowledged_not_done`` response on a new event version (#905)."""

    document = _load_versioned_template(entry, "events/response-recorded-1.0.0.schema.json")
    try:
        properties = cast(dict[str, JsonValue], document["properties"])
        disposition = cast(dict[str, JsonValue], properties["disposition"])
        rules = cast(list[JsonValue], document["oneOf"])
    except (KeyError, TypeError) as exc:
        raise SchemaGenerationError(
            "response_recorded_schema_template_invalid", entries=(entry.relative_path,)
        ) from exc
    _admit_terminal_dispositions(disposition)
    rules.insert(
        1,
        {
            **_no_waiver_fields(),
            "properties": {"disposition": {"const": _ACKNOWLEDGED_NOT_DONE}},
            "required": ["reason"],
        },
    )
    _insert_before_waived(
        rules,
        {
            **_no_waiver_fields(),
            "properties": {
                "disposition": {"const": _SELF_VERIFIED},
                "evidence_refs": {"minItems": 1},
            },
            "required": ["reason", "evidence_refs"],
        },
    )
    _insert_before_waived(
        rules,
        {
            **_no_waiver_fields(),
            "properties": {"disposition": {"const": _REOPENED}},
            "required": ["reason"],
        },
    )
    link_rule = _admit_duplicate_of(properties, rules, one_of=True)
    assert link_rule is not None
    cast(list[JsonValue], document.setdefault("allOf", [])).append(link_rule)
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    return document


def _respond_request_v1_1_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Add the terminal ``acknowledged_not_done`` disposition to ``respond`` (#905)."""

    document = _load_versioned_template(entry, "operations/respond-request-1.0.0.schema.json")
    try:
        properties = cast(dict[str, JsonValue], document["properties"])
        disposition = cast(dict[str, JsonValue], properties["disposition"])
        rules = cast(list[JsonValue], document["allOf"])
    except (KeyError, TypeError) as exc:
        raise SchemaGenerationError(
            "respond_request_schema_template_invalid", entries=(entry.relative_path,)
        ) from exc
    _admit_terminal_dispositions(disposition)
    rules.insert(1, _acknowledged_not_done_condition())
    _insert_before_waived(rules, _self_verified_condition())
    _insert_before_waived(rules, _reopened_condition())
    link_rule = _admit_duplicate_of(properties, rules)
    assert link_rule is not None
    rules.append(link_rule)
    _admit_advisory_dispositions(properties, rules, evidence_field="evidence_refs")
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    if "title" in document:
        document["title"] = f"Yoetz respond request {entry.schema_version}"
    return document


def _respond_result_v1_1_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Echo the terminal ``acknowledged_not_done`` disposition in the respond result (#905)."""

    document = _load_versioned_template(entry, "operations/respond-result-1.0.0.schema.json")
    try:
        definitions = cast(dict[str, JsonValue], document["$defs"])
        response = cast(dict[str, JsonValue], definitions["response"])
        properties = cast(dict[str, JsonValue], response["properties"])
        disposition = cast(dict[str, JsonValue], properties["disposition"])
        rules = cast(list[JsonValue], response["allOf"])
    except (KeyError, TypeError) as exc:
        raise SchemaGenerationError(
            "respond_result_schema_template_invalid", entries=(entry.relative_path,)
        ) from exc
    _admit_terminal_dispositions(disposition)
    rules.insert(1, _acknowledged_not_done_condition())
    _insert_before_waived(rules, _self_verified_condition("evidence"))
    _insert_before_waived(rules, _reopened_condition())
    link_rule = _admit_duplicate_of(properties, rules)
    assert link_rule is not None
    rules.append(link_rule)
    _admit_advisory_dispositions(properties, rules, evidence_field="evidence")
    # tb4n3 RC-7 (#1030): where the finding stands once the answer is recorded.
    definitions["closure_after"] = {
        "additionalProperties": False,
        "properties": {
            "limitation": {
                "enum": [
                    "limitation_acknowledged_not_done",
                    "limitation_disclosed",
                    "limitation_requested",
                ],
                "type": "string",
            },
            "todo_state": {
                "enum": [
                    "acknowledged_not_done",
                    "disputed_after_rebuttal",
                    "open",
                    "rejection_accepted",
                    "self_verified",
                    "verified_resolved",
                ],
                "type": "string",
            },
        },
        "required": ["todo_state"],
        "type": "object",
    }
    success = cast(dict[str, JsonValue], definitions["success"])
    cast(dict[str, JsonValue], success["properties"])["closure_after"] = {
        "$ref": "#/$defs/closure_after"
    }
    _admit_recorded_policy_identities(document)
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    if "title" in document:
        document["title"] = f"Yoetz respond result {entry.schema_version}"
    return document


def _status_request_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Extend the reviewed status filter with the model-owned response disposition."""

    source = (
        Path(__file__).resolve().parent.parent
        / "schemas/operations/status-request-1.0.0.schema.json"
    )
    try:
        document = cast(dict[str, JsonValue], json.loads(source.read_bytes()))
        definitions = cast(dict[str, JsonValue], document["$defs"])
        findings_filter = cast(dict[str, JsonValue], definitions["findings_filter"])
        properties = cast(dict[str, JsonValue], findings_filter["properties"])
        disposition = cast(dict[str, JsonValue], properties["disposition"])
        if not isinstance(disposition, dict):
            raise TypeError("disposition must be an object")
    except (KeyError, OSError, TypeError, json.JSONDecodeError) as exc:
        raise SchemaGenerationError(
            "status_request_schema_template_invalid", entries=(entry.relative_path,)
        ) from exc
    disposition["enum"] = [
        "acknowledged",
        "none",
        "provenance_disputed",
        "rejected",
        "waived",
    ]
    if entry.schema_version == "1.1.0":
        properties = cast(dict[str, JsonValue], document["properties"])
        view = cast(dict[str, JsonValue], properties["view"])
        view_values = cast(list[JsonValue], view["enum"])
        view_values.insert(view_values.index("versions"), "results")
        rules = cast(list[JsonValue], document["allOf"])
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            condition = rule.get("if")
            if not isinstance(condition, dict):
                continue
            condition_properties = condition.get("properties")
            if not isinstance(condition_properties, dict):
                continue
            view_condition = condition_properties.get("view")
            if not isinstance(view_condition, dict):
                continue
            no_filter_values = view_condition.get("enum")
            if isinstance(no_filter_values, list) and "compact" in no_filter_values:
                no_filter_values.append("results")
                break
        document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
        document["title"] = "Yoetz status request 1.1.0"
    return document


_REGISTRY: Final[tuple[_RegistryEntry, ...]] = (
    _RegistryEntry(
        "privacy/review-packet-row-2.0.0.schema.json",
        "review-packet-row",
        "2.0.0",
        "request_result",
        "outbound-case",
        lambda: dict,
    ),
    _RegistryEntry(
        "common/actor-assertion-1.0.0.schema.json",
        "actor-assertion",
        "1.0.0",
        "request_result",
        "common-value",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["ActorAssertionModel"]
            ).ActorAssertionModel
        ),
    ),
    _RegistryEntry(
        "common/client-info-1.0.0.schema.json",
        "client-info",
        "1.0.0",
        "request_result",
        "common-value",
        lambda: (
            __import__("finishup.protocol.models", fromlist=["ClientInfoModel"]).ClientInfoModel
        ),
    ),
    _RegistryEntry(
        "common/coverage-1.0.0.schema.json",
        "coverage",
        "1.0.0",
        "request_result",
        "common-value",
        lambda: __import__("finishup.protocol.coverage", fromlist=["Coverage"]).Coverage,
    ),
    _RegistryEntry(
        "common/frontier-1.0.0.schema.json",
        "frontier",
        "1.0.0",
        "request_result",
        "common-value",
        lambda: __import__("finishup.domain.values", fromlist=["Frontier"]).Frontier,
    ),
    _RegistryEntry(
        "common/lineage-acceptance-1.0.0.schema.json",
        "lineage-acceptance",
        "1.0.0",
        "request_result",
        "common-value",
        lambda: (
            __import__(
                "finishup.domain.coordination", fromlist=["LineageAcceptance"]
            ).LineageAcceptance
        ),
    ),
    _RegistryEntry(
        "common/lineage-origin-1.0.0.schema.json",
        "lineage-origin",
        "1.0.0",
        "request_result",
        "common-value",
        lambda: (
            __import__("finishup.domain.coordination", fromlist=["LineageOrigin"]).LineageOrigin
        ),
    ),
    _RegistryEntry(
        "common/operation-result-1.0.0.schema.json",
        "operation-result",
        "1.0.0",
        "request_result",
        "MCP output",
        _operation_result_schema,
    ),
    _RegistryEntry(
        "common/session-health-1.0.0.schema.json",
        "session-health",
        "1.0.0",
        "request_result",
        "common-value",
        lambda: (
            __import__("finishup.domain.coordination", fromlist=["SessionHealth"]).SessionHealth
        ),
    ),
    _RegistryEntry(
        "common/work-state-1.0.0.schema.json",
        "work-state",
        "1.0.0",
        "request_result",
        "common-value",
        lambda: __import__("finishup.domain.coordination", fromlist=["WorkState"]).WorkState,
    ),
    _RegistryEntry(
        "common/public-error-1.0.0.schema.json",
        "public-error",
        "1.0.0",
        "request_result",
        "common-value",
        lambda: (
            __import__(
                "finishup.protocol.errors", fromlist=["PublicOperationError"]
            ).PublicOperationError
        ),
    ),
    _RegistryEntry(
        "common/subject-state-ref-1.0.0.schema.json",
        "subject-state-ref",
        "1.0.0",
        "request_result",
        "common-value",
        lambda: __import__("finishup.domain.values", fromlist=["SubjectStateRef"]).SubjectStateRef,
    ),
    _RegistryEntry(
        "config/yoetz-config-1.0.0.schema.json",
        "yoetz-config",
        "1.0.0",
        "config",
        "configuration",
        lambda: __import__("finishup.config.models", fromlist=["FinishUpConfig"]).FinishUpConfig,
    ),
    _RegistryEntry(
        "config/yoetz-config-1.1.0.schema.json",
        "yoetz-config",
        "1.1.0",
        "config",
        "configuration",
        lambda: __import__("finishup.config.models", fromlist=["FinishUpConfig"]).FinishUpConfig,
    ),
    _RegistryEntry(
        "config/yoetz-config-1.2.0.schema.json",
        "yoetz-config",
        "1.2.0",
        "config",
        "configuration",
        lambda: __import__("finishup.config.models", fromlist=["FinishUpConfig"]).FinishUpConfig,
    ),
    _RegistryEntry(
        "config/yoetz-config-1.3.0.schema.json",
        "yoetz-config",
        "1.3.0",
        "config",
        "configuration",
        lambda: __import__("finishup.config.models", fromlist=["FinishUpConfig"]).FinishUpConfig,
    ),
    _RegistryEntry(
        "consent/catalog-2.0.0.schema.json",
        "catalog",
        "2.0.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "consent/catalog-3.0.0.schema.json",
        "catalog",
        "3.0.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "consent/catalog-4.0.0.schema.json",
        "catalog",
        "4.0.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "consent/catalog-5.0.0.schema.json",
        "catalog",
        "5.0.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "consent/catalog-6.0.0.schema.json",
        "catalog",
        "6.0.0",
        "request_result",
        "local-control",
        lambda: (
            __import__(
                "finishup.protocol.consent", fromlist=["ConsentCatalogModel"]
            ).ConsentCatalogModel
        ),
    ),
    _RegistryEntry(
        "consent/catalog-7.0.0.schema.json",
        "catalog",
        "7.0.0",
        "request_result",
        "local-control",
        lambda: (
            __import__(
                "finishup.protocol.consent", fromlist=["ConsentCatalogModel"]
            ).ConsentCatalogModel
        ),
    ),
    _RegistryEntry(
        "consent/chat-user-attestation-1.0.0.schema.json",
        "chat-user-attestation",
        "1.0.0",
        "request_result",
        "local-control",
        lambda: (
            __import__(
                "finishup.protocol.chat_user_authority", fromlist=["ChatUserAttestationModel"]
            ).ChatUserAttestationModel
        ),
    ),
    _RegistryEntry(
        "consent/pending-agent-2.0.0.schema.json",
        "pending-agent",
        "2.0.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "consent/pending-agent-3.0.0.schema.json",
        "pending-agent",
        "3.0.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "consent/pending-agent-4.0.0.schema.json",
        "pending-agent",
        "4.0.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "consent/pending-agent-5.0.0.schema.json",
        "pending-agent",
        "5.0.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "consent/pending-agent-6.0.0.schema.json",
        "pending-agent",
        "6.0.0",
        "request_result",
        "local-control",
        lambda: (
            __import__(
                "finishup.protocol.consent", fromlist=["AgentSafePendingModel"]
            ).AgentSafePendingModel
        ),
    ),
    _RegistryEntry(
        "consent/pending-agent-7.0.0.schema.json",
        "pending-agent",
        "7.0.0",
        "request_result",
        "local-control",
        lambda: (
            __import__(
                "finishup.protocol.consent", fromlist=["AgentSafePendingModel"]
            ).AgentSafePendingModel
        ),
    ),
    _RegistryEntry(
        "consent/prepare-result-2.0.0.schema.json",
        "prepare-result",
        "2.0.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "consent/prepare-result-3.0.0.schema.json",
        "prepare-result",
        "3.0.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "consent/prepare-result-4.0.0.schema.json",
        "prepare-result",
        "4.0.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "consent/prepare-result-5.0.0.schema.json",
        "prepare-result",
        "5.0.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "consent/prepare-result-6.0.0.schema.json",
        "prepare-result",
        "6.0.0",
        "request_result",
        "local-control",
        lambda: (
            __import__(
                "finishup.protocol.consent", fromlist=["ConsentPrepareResultModel"]
            ).ConsentPrepareResultModel
        ),
    ),
    _RegistryEntry(
        "consent/prepare-result-7.0.0.schema.json",
        "prepare-result",
        "7.0.0",
        "request_result",
        "local-control",
        lambda: (
            __import__(
                "finishup.protocol.consent", fromlist=["ConsentPrepareResultModel"]
            ).ConsentPrepareResultModel
        ),
    ),
    _RegistryEntry(
        "consent/review-result-2.0.0.schema.json",
        "review-result",
        "2.0.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "consent/review-result-3.0.0.schema.json",
        "review-result",
        "3.0.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "consent/review-result-4.0.0.schema.json",
        "review-result",
        "4.0.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "consent/review-result-5.0.0.schema.json",
        "review-result",
        "5.0.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "consent/review-result-6.0.0.schema.json",
        "review-result",
        "6.0.0",
        "request_result",
        "local-control",
        lambda: (
            __import__(
                "finishup.protocol.consent", fromlist=["ConsentReviewResultModel"]
            ).ConsentReviewResultModel
        ),
    ),
    _RegistryEntry(
        "consent/review-result-7.0.0.schema.json",
        "review-result",
        "7.0.0",
        "request_result",
        "local-control",
        lambda: (
            __import__(
                "finishup.protocol.consent", fromlist=["ConsentReviewResultModel"]
            ).ConsentReviewResultModel
        ),
    ),
    _RegistryEntry(
        "consent/status-2.0.0.schema.json",
        "status",
        "2.0.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "consent/status-3.0.0.schema.json",
        "status",
        "3.0.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "consent/status-4.0.0.schema.json",
        "status",
        "4.0.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "consent/status-5.0.0.schema.json",
        "status",
        "5.0.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "consent/status-6.0.0.schema.json",
        "status",
        "6.0.0",
        "request_result",
        "local-control",
        lambda: (
            __import__(
                "finishup.protocol.consent", fromlist=["ConsentStatusModel"]
            ).ConsentStatusModel
        ),
    ),
    _RegistryEntry(
        "consent/status-7.0.0.schema.json",
        "status",
        "7.0.0",
        "request_result",
        "local-control",
        lambda: (
            __import__(
                "finishup.protocol.consent", fromlist=["ConsentStatusModel"]
            ).ConsentStatusModel
        ),
    ),
    _RegistryEntry(
        "events/accepted-event-1.0.0.schema.json",
        "accepted-event",
        "1.0.0",
        "event",
        "persisted-envelope",
        lambda: __import__("finishup.domain.events", fromlist=["AcceptedEvent"]).AcceptedEvent,
    ),
    _RegistryEntry(
        "observations/routine-read-summary-1.0.0.schema.json",
        "routine-read-summary",
        "1.0.0",
        "request_result",
        "local-control",
        lambda: (
            __import__(
                "finishup.domain.observation", fromlist=["RoutineReadSummary"]
            ).RoutineReadSummary
        ),
    ),
    _RegistryEntry(
        "events/action-recorded-1.0.0.schema.json",
        "action-recorded",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["ActionRecordedPayload"]
            ).ActionRecordedPayload
        ),
    ),
    _RegistryEntry(
        "events/child-accepted-1.0.0.schema.json",
        "child-accepted",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["ChildAcceptedPayload"]
            ).ChildAcceptedPayload
        ),
    ),
    _RegistryEntry(
        "events/child-dependencies-recorded-1.0.0.schema.json",
        "child-dependencies-recorded",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["ChildDependenciesRecordedPayload"]
            ).ChildDependenciesRecordedPayload
        ),
    ),
    _RegistryEntry(
        "events/coordination-context-recorded-1.0.0.schema.json",
        "coordination-context-recorded",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["CoordinationContextRecordedPayload"]
            ).CoordinationContextRecordedPayload
        ),
    ),
    _RegistryEntry(
        "events/coordination-disposition-recorded-1.0.0.schema.json",
        "coordination-disposition-recorded",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["CoordinationDispositionRecordedPayload"]
            ).CoordinationDispositionRecordedPayload
        ),
    ),
    _RegistryEntry(
        "events/coordination-obligation-declared-1.0.0.schema.json",
        "coordination-obligation-declared",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["CoordinationObligationDeclaredPayload"]
            ).CoordinationObligationDeclaredPayload
        ),
    ),
    _RegistryEntry(
        "events/child-rejected-1.0.0.schema.json",
        "child-rejected",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["ChildRejectedPayload"]
            ).ChildRejectedPayload
        ),
    ),
    _RegistryEntry(
        "events/child-written-off-1.0.0.schema.json",
        "child-written-off",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["ChildWrittenOffPayload"]
            ).ChildWrittenOffPayload
        ),
    ),
    _RegistryEntry(
        "events/assignment-recorded-1.0.0.schema.json",
        "assignment-recorded",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["AssignmentRecordedPayload"]
            ).AssignmentRecordedPayload
        ),
    ),
    _RegistryEntry(
        "events/check-recorded-1.0.0.schema.json",
        "check-recorded",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["CheckRecordedPayload"]
            ).CheckRecordedPayload
        ),
    ),
    _RegistryEntry(
        "events/check-recorded-1.1.0.schema.json",
        "check-recorded",
        "1.1.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["CheckRecordedPayload"]
            ).CheckRecordedPayload
        ),
    ),
    _RegistryEntry(
        "events/check-recorded-1.2.0.schema.json",
        "check-recorded",
        "1.2.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["CheckRecordedPayload"]
            ).CheckRecordedPayload
        ),
    ),
    _RegistryEntry(
        "events/check-recorded-1.3.0.schema.json",
        "check-recorded",
        "1.3.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["CheckRecordedPayload"]
            ).CheckRecordedPayload
        ),
    ),
    _RegistryEntry(
        "events/check-recorded-1.4.0.schema.json",
        "check-recorded",
        "1.4.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["CheckRecordedPayload"]
            ).CheckRecordedPayload
        ),
    ),
    _RegistryEntry(
        "events/check-recorded-1.5.0.schema.json",
        "check-recorded",
        "1.5.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["CheckRecordedPayload"]
            ).CheckRecordedPayload
        ),
    ),
    _RegistryEntry(
        "events/check-recorded-1.6.0.schema.json",
        "check-recorded",
        "1.6.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["CheckRecordedPayload"]
            ).CheckRecordedPayload
        ),
    ),
    _RegistryEntry(
        "events/claim-recorded-1.0.0.schema.json",
        "claim-recorded",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["ClaimRecordedPayload"]
            ).ClaimRecordedPayload
        ),
    ),
    _RegistryEntry(
        "events/claim-recorded-1.1.0.schema.json",
        "claim-recorded",
        "1.1.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["ClaimRecordedPayloadV1_1"]
            ).ClaimRecordedPayloadV1_1
        ),
    ),
    _RegistryEntry(
        "events/decision-recorded-1.0.0.schema.json",
        "decision-recorded",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["DecisionRecordedPayload"]
            ).DecisionRecordedPayload
        ),
    ),
    _RegistryEntry(
        "events/decision-recorded-1.1.0.schema.json",
        "decision-recorded",
        "1.1.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["DecisionRecordedPayload"]
            ).DecisionRecordedPayload
        ),
    ),
    _RegistryEntry(
        "events/delegation-cancelled-1.0.0.schema.json",
        "delegation-cancelled",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["DelegationCancelledPayload"]
            ).DelegationCancelledPayload
        ),
    ),
    _RegistryEntry(
        "events/delegation-declared-1.0.0.schema.json",
        "delegation-declared",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["DelegationDeclaredPayload"]
            ).DelegationDeclaredPayload
        ),
    ),
    _RegistryEntry(
        "events/event-draft-1.0.0.schema.json",
        "event-draft",
        "1.0.0",
        "event",
        "event-envelope",
        lambda: __import__("finishup.domain.events", fromlist=["EventDraft"]).EventDraft,
    ),
    _RegistryEntry(
        "events/event-draft-1.1.0.schema.json",
        "event-draft",
        "1.1.0",
        "event",
        "event-envelope",
        lambda: __import__("finishup.domain.events", fromlist=["EventDraft"]).EventDraft,
    ),
    _RegistryEntry(
        "events/event-draft-1.2.0.schema.json",
        "event-draft",
        "1.2.0",
        "event",
        "event-envelope",
        lambda: __import__("finishup.domain.events", fromlist=["EventDraft"]).EventDraft,
    ),
    _RegistryEntry(
        "events/evidence-recorded-1.0.0.schema.json",
        "evidence-recorded",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["EvidenceRecordedPayload"]
            ).EvidenceRecordedPayload
        ),
    ),
    _RegistryEntry(
        "events/evidence-recorded-1.1.0.schema.json",
        "evidence-recorded",
        "1.1.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["EvidenceRecordedPayload"]
            ).EvidenceRecordedPayload
        ),
    ),
    _RegistryEntry(
        "events/evidence-recorded-1.2.0.schema.json",
        "evidence-recorded",
        "1.2.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["EvidenceRecordedPayload"]
            ).EvidenceRecordedPayload
        ),
    ),
    _RegistryEntry(
        "events/finding-recorded-1.0.0.schema.json",
        "finding-recorded",
        "1.0.0",
        "event",
        "event-payload",
        lambda: __import__("finishup.domain.findings", fromlist=["Finding"]).Finding,
    ),
    _RegistryEntry(
        "events/finding-recorded-1.1.0.schema.json",
        "finding-recorded",
        "1.1.0",
        "event",
        "event-payload",
        lambda: __import__("finishup.domain.findings", fromlist=["Finding"]).Finding,
    ),
    _RegistryEntry(
        "events/finding-recorded-1.2.0.schema.json",
        "finding-recorded",
        "1.2.0",
        "event",
        "event-payload",
        None,
    ),
    _RegistryEntry(
        "events/finding-recorded-1.3.0.schema.json",
        "finding-recorded",
        "1.3.0",
        "event",
        "event-payload",
        lambda: __import__("finishup.domain.findings", fromlist=["Finding"]).Finding,
    ),
    _RegistryEntry(
        "events/finding-recorded-1.4.0.schema.json",
        "finding-recorded",
        "1.4.0",
        "event",
        "event-payload",
        lambda: __import__("finishup.domain.findings", fromlist=["Finding"]).Finding,
    ),
    _RegistryEntry(
        "events/obligation-published-1.0.0.schema.json",
        "obligation-published",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["ObligationPublishedPayload"]
            ).ObligationPublishedPayload
        ),
    ),
    _RegistryEntry(
        "events/obligation-published-1.1.0.schema.json",
        "obligation-published",
        "1.1.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["ObligationPublishedPayload"]
            ).ObligationPublishedPayload
        ),
    ),
    _RegistryEntry(
        "events/opaque-unknown-event-draft-1.0.0.schema.json",
        "opaque-unknown-event-draft",
        "1.0.0",
        "event",
        "event-envelope",
        lambda: __import__("finishup.domain.events", fromlist=["UnknownEvent"]).UnknownEvent,
    ),
    _RegistryEntry(
        "events/opaque-unknown-event-draft-1.1.0.schema.json",
        "opaque-unknown-event-draft",
        "1.1.0",
        "event",
        "event-envelope",
        lambda: __import__("finishup.domain.events", fromlist=["UnknownEvent"]).UnknownEvent,
    ),
    _RegistryEntry(
        "events/opaque-unknown-event-draft-1.2.0.schema.json",
        "opaque-unknown-event-draft",
        "1.2.0",
        "event",
        "event-envelope",
        lambda: __import__("finishup.domain.events", fromlist=["UnknownEvent"]).UnknownEvent,
    ),
    _RegistryEntry(
        "events/plan-published-1.0.0.schema.json",
        "plan-published",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["PlanPublishedPayload"]
            ).PlanPublishedPayload
        ),
    ),
    _RegistryEntry(
        "events/plan-published-1.1.0.schema.json",
        "plan-published",
        "1.1.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["PlanPublishedPayload"]
            ).PlanPublishedPayload
        ),
    ),
    _RegistryEntry(
        "events/plan-revised-1.0.0.schema.json",
        "plan-revised",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__("finishup.domain.events", fromlist=["PlanRevisedPayload"]).PlanRevisedPayload
        ),
    ),
    _RegistryEntry(
        "events/plan-revised-1.1.0.schema.json",
        "plan-revised",
        "1.1.0",
        "event",
        "event-payload",
        lambda: (
            __import__("finishup.domain.events", fromlist=["PlanRevisedPayload"]).PlanRevisedPayload
        ),
    ),
    _RegistryEntry(
        "events/receipt-recorded-1.0.0.schema.json",
        "receipt-recorded",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["ReceiptRecordedPayload"]
            ).ReceiptRecordedPayload
        ),
    ),
    _RegistryEntry(
        "events/redaction-recorded-1.0.0.schema.json",
        "redaction-recorded",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["RedactionRecordedPayload"]
            ).RedactionRecordedPayload
        ),
    ),
    _RegistryEntry(
        "events/response-recorded-1.0.0.schema.json",
        "response-recorded",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["ResponseRecordedPayload"]
            ).ResponseRecordedPayload
        ),
    ),
    _RegistryEntry(
        "events/response-recorded-1.1.0.schema.json",
        "response-recorded",
        "1.1.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["ResponseRecordedPayload"]
            ).ResponseRecordedPayload
        ),
    ),
    _RegistryEntry(
        "events/result-recorded-1.0.0.schema.json",
        "result-recorded",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["ResultRecordedPayload"]
            ).ResultRecordedPayload
        ),
    ),
    _RegistryEntry(
        "events/result-recorded-1.1.0.schema.json",
        "result-recorded",
        "1.1.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["ResultRecordedPayload"]
            ).ResultRecordedPayload
        ),
    ),
    _RegistryEntry(
        "events/session-opened-1.0.0.schema.json",
        "session-opened",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["SessionOpenedPayload"]
            ).SessionOpenedPayload
        ),
    ),
    _RegistryEntry(
        "events/session-opened-1.1.0.schema.json",
        "session-opened",
        "1.1.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["SessionOpenedPayload"]
            ).SessionOpenedPayload
        ),
    ),
    _RegistryEntry(
        "events/session-opened-1.2.0.schema.json",
        "session-opened",
        "1.2.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["SessionOpenedPayload"]
            ).SessionOpenedPayload
        ),
    ),
    _RegistryEntry(
        "events/session-resumed-1.0.0.schema.json",
        "session-resumed",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["SessionResumedPayload"]
            ).SessionResumedPayload
        ),
    ),
    _RegistryEntry(
        "events/session-resumed-1.1.0.schema.json",
        "session-resumed",
        "1.1.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["SessionResumedPayload"]
            ).SessionResumedPayload
        ),
    ),
    _RegistryEntry(
        "events/session-resumed-1.2.0.schema.json",
        "session-resumed",
        "1.2.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["SessionResumedPayload"]
            ).SessionResumedPayload
        ),
    ),
    _RegistryEntry(
        "events/work-abandoned-1.0.0.schema.json",
        "work-abandoned",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["WorkAbandonedPayload"]
            ).WorkAbandonedPayload
        ),
    ),
    _RegistryEntry(
        "events/work-cancelled-1.0.0.schema.json",
        "work-cancelled",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["WorkCancelledPayload"]
            ).WorkCancelledPayload
        ),
    ),
    _RegistryEntry(
        "events/work-closed-1.0.0.schema.json",
        "work-closed",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__("finishup.domain.events", fromlist=["WorkClosedPayload"]).WorkClosedPayload
        ),
    ),
    _RegistryEntry(
        "events/work-written-off-1.0.0.schema.json",
        "work-written-off",
        "1.0.0",
        "event",
        "event-payload",
        lambda: (
            __import__(
                "finishup.domain.events", fromlist=["WorkWrittenOffPayload"]
            ).WorkWrittenOffPayload
        ),
    ),
    _RegistryEntry(
        "findings/finding-1.0.0.schema.json",
        "finding",
        "1.0.0",
        "request_result",
        "finding",
        lambda: __import__("finishup.domain.findings", fromlist=["Finding"]).Finding,
    ),
    _RegistryEntry(
        "findings/finding-1.1.0.schema.json",
        "finding",
        "1.1.0",
        "request_result",
        "finding",
        lambda: __import__("finishup.domain.findings", fromlist=["Finding"]).Finding,
    ),
    _RegistryEntry(
        "findings/finding-1.2.0.schema.json",
        "finding",
        "1.2.0",
        "request_result",
        "finding",
        None,
    ),
    _RegistryEntry(
        "findings/finding-1.3.0.schema.json",
        "finding",
        "1.3.0",
        "request_result",
        "finding",
        lambda: __import__("finishup.domain.findings", fromlist=["Finding"]).Finding,
    ),
    _RegistryEntry(
        "findings/finding-1.4.0.schema.json",
        "finding",
        "1.4.0",
        "request_result",
        "finding",
        lambda: __import__("finishup.domain.findings", fromlist=["Finding"]).Finding,
    ),
    _RegistryEntry(
        "findings/semantic-provenance-1.0.0.schema.json",
        "semantic-provenance",
        "1.0.0",
        "request_result",
        "semantic-provenance",
        lambda: (
            __import__(
                "finishup.domain.findings", fromlist=["SemanticProvenance"]
            ).SemanticProvenance
        ),
    ),
    _RegistryEntry(
        "findings/semantic-provenance-1.1.0.schema.json",
        "semantic-provenance",
        "1.1.0",
        "request_result",
        "semantic-provenance",
        lambda: (
            __import__(
                "finishup.domain.findings", fromlist=["SemanticProvenance"]
            ).SemanticProvenance
        ),
    ),
    _RegistryEntry(
        "findings/semantic-provenance-1.2.0.schema.json",
        "semantic-provenance",
        "1.2.0",
        "request_result",
        "semantic-provenance",
        lambda: (
            __import__(
                "finishup.domain.findings", fromlist=["SemanticProvenance"]
            ).SemanticProvenance
        ),
    ),
    _RegistryEntry(
        "findings/runtime-attempt-evidence-1.0.0.schema.json",
        "runtime-attempt-evidence",
        "1.0.0",
        "request_result",
        "semantic-provenance",
        lambda: (
            __import__(
                "finishup.domain.findings", fromlist=["RuntimeAttemptEvidence"]
            ).RuntimeAttemptEvidence
        ),
    ),
    _RegistryEntry(
        "findings/runtime-attempt-evidence-1.1.0.schema.json",
        "runtime-attempt-evidence",
        "1.1.0",
        "request_result",
        "semantic-provenance",
        lambda: (
            __import__(
                "finishup.domain.findings", fromlist=["RuntimeAttemptEvidence"]
            ).RuntimeAttemptEvidence
        ),
    ),
    _RegistryEntry(
        "findings/provider-judgment-1.0.0.schema.json",
        "provider-judgment",
        "1.0.0",
        "request_result",
        "provider-judgment",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["ProviderJudgmentEnvelopeModel"]
            ).ProviderJudgmentEnvelopeModel
        ),
    ),
    _RegistryEntry(
        "findings/provider-judgment-1.1.0.schema.json",
        "provider-judgment",
        "1.1.0",
        "request_result",
        "provider-judgment",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["ProviderJudgmentEnvelopeModel"]
            ).ProviderJudgmentEnvelopeModel
        ),
    ),
    _RegistryEntry(
        "findings/provider-judgment-1.2.0.schema.json",
        "provider-judgment",
        "1.2.0",
        "request_result",
        "provider-judgment",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["ProviderJudgmentEnvelopeModel"]
            ).ProviderJudgmentEnvelopeModel
        ),
    ),
    # The reviewer loop's one reply per turn: a read action or the final judgment (#1118).
    _RegistryEntry(
        "findings/reviewer-reply-1.0.0.schema.json",
        "reviewer-reply",
        "1.0.0",
        "request_result",
        "provider-judgment",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["ReviewerActionModel"]
            ).ReviewerActionModel
        ),
    ),
    _RegistryEntry(
        "operations/check-request-1.0.0.schema.json",
        "check-request",
        "1.0.0",
        "request_result",
        "MCP input",
        lambda: (
            __import__("finishup.protocol.models", fromlist=["CheckRequestModel"]).CheckRequestModel
        ),
    ),
    _RegistryEntry(
        "operations/check-request-1.1.0.schema.json",
        "check-request",
        "1.1.0",
        "request_result",
        "MCP input",
        lambda: (
            __import__("finishup.protocol.models", fromlist=["CheckRequestModel"]).CheckRequestModel
        ),
    ),
    _RegistryEntry(
        "operations/check-result-1.0.0.schema.json",
        "check-result",
        "1.0.0",
        "request_result",
        "MCP output",
        lambda: (
            __import__("finishup.protocol.models", fromlist=["CheckResultModel"]).CheckResultModel
        ),
    ),
    _RegistryEntry(
        "operations/check-result-1.1.0.schema.json",
        "check-result",
        "1.1.0",
        "request_result",
        "MCP output",
        lambda: (
            __import__("finishup.protocol.models", fromlist=["CheckResultModel"]).CheckResultModel
        ),
    ),
    _RegistryEntry(
        "operations/check-result-1.2.0.schema.json",
        "check-result",
        "1.2.0",
        "request_result",
        "MCP output",
        None,
    ),
    _RegistryEntry(
        "operations/check-result-1.3.0.schema.json",
        "check-result",
        "1.3.0",
        "request_result",
        "MCP output",
        lambda: (
            __import__("finishup.protocol.models", fromlist=["CheckResultModel"]).CheckResultModel
        ),
    ),
    _RegistryEntry(
        "operations/check-result-1.4.0.schema.json",
        "check-result",
        "1.4.0",
        "request_result",
        "MCP output",
        lambda: (
            __import__("finishup.protocol.models", fromlist=["CheckResultModel"]).CheckResultModel
        ),
    ),
    _RegistryEntry(
        "operations/check-result-1.5.0.schema.json",
        "check-result",
        "1.5.0",
        "request_result",
        "MCP output",
        lambda: (
            __import__("finishup.protocol.models", fromlist=["CheckResultModel"]).CheckResultModel
        ),
    ),
    _RegistryEntry(
        "operations/check-result-1.6.0.schema.json",
        "check-result",
        "1.6.0",
        "request_result",
        "MCP output",
        lambda: (
            __import__("finishup.protocol.models", fromlist=["CheckResultModel"]).CheckResultModel
        ),
    ),
    _RegistryEntry(
        "operations/closure-prepare-request-1.0.0.schema.json",
        "closure-prepare-request",
        "1.0.0",
        "request_result",
        "MCP input",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["ClosurePrepareRequestModel"]
            ).ClosurePrepareRequestModel
        ),
    ),
    _RegistryEntry(
        "operations/closure-prepare-result-1.0.0.schema.json",
        "closure-prepare-result",
        "1.0.0",
        "request_result",
        "MCP output",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["ClosurePrepareResultModel"]
            ).ClosurePrepareResultModel
        ),
    ),
    _RegistryEntry(
        "operations/publish-work-request-1.0.0.schema.json",
        "publish-work-request",
        "1.0.0",
        "request_result",
        "MCP input",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["PublishWorkRequestModel"]
            ).PublishWorkRequestModel
        ),
    ),
    _RegistryEntry(
        "operations/publish-work-request-1.1.0.schema.json",
        "publish-work-request",
        "1.1.0",
        "request_result",
        "MCP input",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["PublishWorkRequestModel"]
            ).PublishWorkRequestModel
        ),
    ),
    _RegistryEntry(
        "operations/publish-work-request-1.2.0.schema.json",
        "publish-work-request",
        "1.2.0",
        "request_result",
        "MCP input",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["PublishWorkRequestModel"]
            ).PublishWorkRequestModel
        ),
    ),
    _RegistryEntry(
        "operations/publish-work-result-1.0.0.schema.json",
        "publish-work-result",
        "1.0.0",
        "request_result",
        "MCP output",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["PublishWorkResultModel"]
            ).PublishWorkResultModel
        ),
    ),
    _RegistryEntry(
        "operations/publish-work-result-1.1.0.schema.json",
        "publish-work-result",
        "1.1.0",
        "request_result",
        "MCP output",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["PublishWorkResultModel"]
            ).PublishWorkResultModel
        ),
    ),
    _RegistryEntry(
        "operations/read-guidance-request-1.0.0.schema.json",
        "read-guidance-request",
        "1.0.0",
        "request_result",
        "MCP input",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["ReadGuidanceRequestModel"]
            ).ReadGuidanceRequestModel
        ),
    ),
    _RegistryEntry(
        "operations/read-guidance-result-1.0.0.schema.json",
        "read-guidance-result",
        "1.0.0",
        "request_result",
        "MCP output",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["ReadGuidanceResultModel"]
            ).ReadGuidanceResultModel
        ),
    ),
    _RegistryEntry(
        "operations/read-guidance-request-1.1.0.schema.json",
        "read-guidance-request",
        "1.1.0",
        "request_result",
        "MCP input",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["ReadGuidanceRequestModel"]
            ).ReadGuidanceRequestModel
        ),
    ),
    _RegistryEntry(
        "operations/read-guidance-result-1.1.0.schema.json",
        "read-guidance-result",
        "1.1.0",
        "request_result",
        "MCP output",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["ReadGuidanceResultModel"]
            ).ReadGuidanceResultModel
        ),
    ),
    _RegistryEntry(
        "operations/receipt-request-1.0.0.schema.json",
        "receipt-request",
        "1.0.0",
        "request_result",
        "MCP input",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["ReceiptRequestModel"]
            ).ReceiptRequestModel
        ),
    ),
    _RegistryEntry(
        "operations/receipt-result-1.0.0.schema.json",
        "receipt-result",
        "1.0.0",
        "request_result",
        "MCP output",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["ReceiptResultModel"]
            ).ReceiptResultModel
        ),
    ),
    _RegistryEntry(
        "operations/receipt-result-1.1.0.schema.json",
        "receipt-result",
        "1.1.0",
        "request_result",
        "MCP output",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["ReceiptResultModel"]
            ).ReceiptResultModel
        ),
    ),
    _RegistryEntry(
        "operations/receipt-result-1.2.0.schema.json",
        "receipt-result",
        "1.2.0",
        "request_result",
        "MCP output",
        None,
    ),
    _RegistryEntry(
        "operations/receipt-result-1.3.0.schema.json",
        "receipt-result",
        "1.3.0",
        "request_result",
        "MCP output",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["ReceiptResultModel"]
            ).ReceiptResultModel
        ),
    ),
    _RegistryEntry(
        "operations/respond-request-1.0.0.schema.json",
        "respond-request",
        "1.0.0",
        "request_result",
        "MCP input",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["RespondRequestModel"]
            ).RespondRequestModel
        ),
    ),
    _RegistryEntry(
        "operations/respond-result-1.0.0.schema.json",
        "respond-result",
        "1.0.0",
        "request_result",
        "MCP output",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["RespondResultModel"]
            ).RespondResultModel
        ),
    ),
    _RegistryEntry(
        "operations/respond-request-1.1.0.schema.json",
        "respond-request",
        "1.1.0",
        "request_result",
        "MCP input",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["RespondRequestModel"]
            ).RespondRequestModel
        ),
    ),
    _RegistryEntry(
        "operations/respond-result-1.1.0.schema.json",
        "respond-result",
        "1.1.0",
        "request_result",
        "MCP output",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["RespondResultModel"]
            ).RespondResultModel
        ),
    ),
    _RegistryEntry(
        "operations/start-request-1.0.0.schema.json",
        "start-request",
        "1.0.0",
        "request_result",
        "MCP input",
        lambda: (
            __import__("finishup.protocol.models", fromlist=["StartRequestModel"]).StartRequestModel
        ),
    ),
    _RegistryEntry(
        "operations/start-request-1.1.0.schema.json",
        "start-request",
        "1.1.0",
        "request_result",
        "MCP input",
        lambda: (
            __import__("finishup.protocol.models", fromlist=["StartRequestModel"]).StartRequestModel
        ),
    ),
    _RegistryEntry(
        "operations/start-result-1.0.0.schema.json",
        "start-result",
        "1.0.0",
        "request_result",
        "MCP output",
        lambda: (
            __import__("finishup.protocol.models", fromlist=["StartResultModel"]).StartResultModel
        ),
    ),
    _RegistryEntry(
        "operations/start-result-1.1.0.schema.json",
        "start-result",
        "1.1.0",
        "request_result",
        "MCP output",
        lambda: (
            __import__("finishup.protocol.models", fromlist=["StartResultModel"]).StartResultModel
        ),
    ),
    _RegistryEntry(
        "operations/status-request-1.0.0.schema.json",
        "status-request",
        "1.0.0",
        "request_result",
        "MCP input",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["StatusRequestModel"]
            ).StatusRequestModel
        ),
    ),
    _RegistryEntry(
        "operations/status-result-1.0.0.schema.json",
        "status-result",
        "1.0.0",
        "request_result",
        "MCP output",
        lambda: (
            __import__("finishup.protocol.models", fromlist=["StatusResultModel"]).StatusResultModel
        ),
    ),
    _RegistryEntry(
        "operations/status-request-1.1.0.schema.json",
        "status-request",
        "1.1.0",
        "request_result",
        "MCP input",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["StatusRequestModel"]
            ).StatusRequestModel
        ),
    ),
    _RegistryEntry(
        "operations/check-result-1.7.0.schema.json",
        "check-result",
        "1.7.0",
        "request_result",
        "MCP output",
        lambda: (
            __import__("finishup.protocol.models", fromlist=["CheckResultModel"]).CheckResultModel
        ),
    ),
    _RegistryEntry(
        "operations/receipt-result-1.4.0.schema.json",
        "receipt-result",
        "1.4.0",
        "request_result",
        "MCP output",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["ReceiptResultModel"]
            ).ReceiptResultModel
        ),
    ),
    _RegistryEntry(
        "operations/status-result-1.5.0.schema.json",
        "status-result",
        "1.5.0",
        "request_result",
        "MCP output",
        lambda: (
            __import__("finishup.protocol.models", fromlist=["StatusResultModel"]).StatusResultModel
        ),
    ),
    _RegistryEntry(
        "operations/status-request-1.3.0.schema.json",
        "status-request",
        "1.3.0",
        "request_result",
        "MCP input",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["StatusRequestModel"]
            ).StatusRequestModel
        ),
    ),
    _RegistryEntry(
        "operations/status-request-1.2.0.schema.json",
        "status-request",
        "1.2.0",
        "request_result",
        "MCP input",
        lambda: (
            __import__(
                "finishup.protocol.models", fromlist=["StatusRequestModel"]
            ).StatusRequestModel
        ),
    ),
    _RegistryEntry(
        "operations/status-result-1.1.0.schema.json",
        "status-result",
        "1.1.0",
        "request_result",
        "MCP output",
        lambda: (
            __import__("finishup.protocol.models", fromlist=["StatusResultModel"]).StatusResultModel
        ),
    ),
    _RegistryEntry(
        "operations/status-result-1.2.0.schema.json",
        "status-result",
        "1.2.0",
        "request_result",
        "MCP output",
        lambda: (
            __import__("finishup.protocol.models", fromlist=["StatusResultModel"]).StatusResultModel
        ),
    ),
    _RegistryEntry(
        "operations/status-result-1.3.0.schema.json",
        "status-result",
        "1.3.0",
        "request_result",
        "MCP output",
        None,
    ),
    _RegistryEntry(
        "operations/status-result-1.4.0.schema.json",
        "status-result",
        "1.4.0",
        "request_result",
        "MCP output",
        lambda: (
            __import__("finishup.protocol.models", fromlist=["StatusResultModel"]).StatusResultModel
        ),
    ),
    _RegistryEntry(
        "privacy/egress-receipt-1.0.0.schema.json",
        "egress-receipt",
        "1.0.0",
        "request_result",
        "privacy-audit",
        lambda: __import__("finishup.domain.privacy", fromlist=["EgressReceipt"]).EgressReceipt,
    ),
    _RegistryEntry(
        "privacy/egress-receipt-1.1.0.schema.json",
        "egress-receipt",
        "1.1.0",
        "request_result",
        "privacy-audit",
        lambda: __import__("finishup.domain.privacy", fromlist=["EgressReceipt"]).EgressReceipt,
    ),
    _RegistryEntry(
        "privacy/outbound-case-1.0.0.schema.json",
        "outbound-case",
        "1.0.0",
        "request_result",
        "outbound-case",
        lambda: (
            __import__(
                "finishup.domain.privacy", fromlist=["ApprovedOutboundCase"]
            ).ApprovedOutboundCase
        ),
    ),
    _RegistryEntry(
        "privacy/outbound-case-1.1.0.schema.json",
        "outbound-case",
        "1.1.0",
        "request_result",
        "outbound-case",
        lambda: (
            __import__(
                "finishup.domain.privacy", fromlist=["ApprovedOutboundCase"]
            ).ApprovedOutboundCase
        ),
    ),
    _RegistryEntry(
        "privacy/outbound-case-1.2.0.schema.json",
        "outbound-case",
        "1.2.0",
        "request_result",
        "outbound-case",
        lambda: (
            __import__(
                "finishup.domain.privacy", fromlist=["ApprovedOutboundCase"]
            ).ApprovedOutboundCase
        ),
    ),
    _RegistryEntry(
        "privacy/privacy-policy-1.0.0.schema.json",
        "privacy-policy",
        "1.0.0",
        "request_result",
        "privacy-policy",
        lambda: __import__("finishup.domain.privacy", fromlist=["PrivacyPolicy"]).PrivacyPolicy,
    ),
    _RegistryEntry(
        "privacy/privacy-policy-1.1.0.schema.json",
        "privacy-policy",
        "1.1.0",
        "request_result",
        "privacy-policy",
        lambda: __import__("finishup.domain.privacy", fromlist=["PrivacyPolicy"]).PrivacyPolicy,
    ),
    _RegistryEntry(
        "privacy/privacy-policy-1.2.0.schema.json",
        "privacy-policy",
        "1.2.0",
        "request_result",
        "privacy-policy",
        lambda: __import__("finishup.domain.privacy", fromlist=["PrivacyPolicy"]).PrivacyPolicy,
    ),
    _RegistryEntry(
        "privacy/privacy-policy-1.3.0.schema.json",
        "privacy-policy",
        "1.3.0",
        "request_result",
        "privacy-policy",
        lambda: __import__("finishup.domain.privacy", fromlist=["PrivacyPolicy"]).PrivacyPolicy,
    ),
    _RegistryEntry(
        "privacy/setup-wizard-contract-1.0.0.schema.json",
        "setup-wizard-contract",
        "1.0.0",
        "request_result",
        "setup-contract",
        None,
    ),
    _RegistryEntry(
        "integrations/mcp-removal-1.0.0.schema.json",
        "mcp-removal",
        "1.0.0",
        "request_result",
        "setup-contract",
        lambda: (
            __import__(
                "finishup.protocol.mcp_removal", fromlist=["McpRemovalContract"]
            ).McpRemovalContract
        ),
    ),
    _RegistryEntry(
        "integrations/setup-readiness-1.0.0.schema.json",
        "setup-readiness",
        "1.0.0",
        "request_result",
        "setup-contract",
        lambda: (
            __import__(
                "finishup.protocol.setup_readiness", fromlist=["SetupReadiness"]
            ).SetupReadiness
        ),
    ),
    _RegistryEntry(
        "integrations/host-connection-1.0.0.schema.json",
        "host-connection",
        "1.0.0",
        "request_result",
        "setup-contract",
        lambda: (
            __import__(
                "finishup.protocol.host_connection", fromlist=["HostConnectionContract"]
            ).HostConnectionContract
        ),
    ),
    _RegistryEntry(
        "integrations/ai-status-1.0.0.schema.json",
        "ai-status",
        "1.0.0",
        "request_result",
        "setup-contract",
        lambda: __import__("finishup.protocol.ai_status", fromlist=["AIStatus"]).AIStatus,
    ),
    _RegistryEntry(
        "integrations/setup-status-2.0.0.schema.json",
        "setup-status",
        "2.0.0",
        "request_result",
        "setup-contract",
        lambda: __import__("finishup.protocol.setup_status", fromlist=["SetupStatus"]).SetupStatus,
    ),
    _RegistryEntry(
        "integrations/host-connection-batch-1.0.0.schema.json",
        "host-connection-batch",
        "1.0.0",
        "request_result",
        "setup-contract",
        lambda: (
            __import__(
                "finishup.protocol.host_connection", fromlist=["HostConnectionBatchReport"]
            ).HostConnectionBatchReport
        ),
    ),
    _RegistryEntry(
        "receipts/receipt-document-1.0.0.schema.json",
        "receipt-document",
        "1.0.0",
        "request_result",
        "receipt-document",
        lambda: (
            __import__("finishup.domain.receipts", fromlist=["ReceiptDocument"]).ReceiptDocument
        ),
    ),
    _RegistryEntry(
        "receipts/receipt-document-1.1.0.schema.json",
        "receipt-document",
        "1.1.0",
        "request_result",
        "receipt-document",
        lambda: (
            __import__("finishup.domain.receipts", fromlist=["ReceiptDocument"]).ReceiptDocument
        ),
    ),
    _RegistryEntry(
        "receipts/receipt-document-1.2.0.schema.json",
        "receipt-document",
        "1.2.0",
        "request_result",
        "receipt-document",
        None,
    ),
    _RegistryEntry(
        "receipts/receipt-document-1.3.0.schema.json",
        "receipt-document",
        "1.3.0",
        "request_result",
        "receipt-document",
        lambda: (
            __import__("finishup.domain.receipts", fromlist=["ReceiptDocument"]).ReceiptDocument
        ),
    ),
    _RegistryEntry(
        "service/control-hello-1.0.0.schema.json",
        "control-hello",
        "1.0.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-hello-result-1.0.0.schema.json",
        "control-hello-result",
        "1.0.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-hello-2.0.0.schema.json",
        "control-hello",
        "2.0.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-hello-result-2.0.0.schema.json",
        "control-hello-result",
        "2.0.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-request-1.0.0.schema.json",
        "control-request",
        "1.0.0",
        "request_result",
        "local-control",
        lambda: __import__("finishup.ports.control", fromlist=["ControlRequest"]).ControlRequest,
    ),
    _RegistryEntry(
        "service/control-result-1.0.0.schema.json",
        "control-result",
        "1.0.0",
        "request_result",
        "local-control",
        lambda: __import__("finishup.ports.control", fromlist=["ControlResult"]).ControlResult,
    ),
    _RegistryEntry(
        "service/control-request-2.0.0.schema.json",
        "control-request",
        "2.0.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-result-2.0.0.schema.json",
        "control-result",
        "2.0.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-hello-2.1.0.schema.json",
        "control-hello",
        "2.1.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-hello-result-2.1.0.schema.json",
        "control-hello-result",
        "2.1.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-request-2.1.0.schema.json",
        "control-request",
        "2.1.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-result-2.1.0.schema.json",
        "control-result",
        "2.1.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-hello-2.2.0.schema.json",
        "control-hello",
        "2.2.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-hello-result-2.2.0.schema.json",
        "control-hello-result",
        "2.2.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-request-2.2.0.schema.json",
        "control-request",
        "2.2.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-result-2.2.0.schema.json",
        "control-result",
        "2.2.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-hello-2.3.0.schema.json",
        "control-hello",
        "2.3.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-hello-result-2.3.0.schema.json",
        "control-hello-result",
        "2.3.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-request-2.3.0.schema.json",
        "control-request",
        "2.3.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-result-2.3.0.schema.json",
        "control-result",
        "2.3.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-hello-2.4.0.schema.json",
        "control-hello",
        "2.4.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-hello-result-2.4.0.schema.json",
        "control-hello-result",
        "2.4.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-request-2.4.0.schema.json",
        "control-request",
        "2.4.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-result-2.4.0.schema.json",
        "control-result",
        "2.4.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-hello-2.5.0.schema.json",
        "control-hello",
        "2.5.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-hello-result-2.5.0.schema.json",
        "control-hello-result",
        "2.5.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-request-2.5.0.schema.json",
        "control-request",
        "2.5.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-result-2.5.0.schema.json",
        "control-result",
        "2.5.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-hello-2.6.0.schema.json",
        "control-hello",
        "2.6.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-hello-result-2.6.0.schema.json",
        "control-hello-result",
        "2.6.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-request-2.6.0.schema.json",
        "control-request",
        "2.6.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-result-2.6.0.schema.json",
        "control-result",
        "2.6.0",
        "request_result",
        "local-control",
        None,
    ),
    _RegistryEntry(
        "service/control-request-2.6.1.schema.json",
        "control-request",
        "2.6.1",
        "request_result",
        "local-control",
        lambda: dict,
    ),
    _RegistryEntry(
        "service/control-result-2.6.1.schema.json",
        "control-result",
        "2.6.1",
        "request_result",
        "local-control",
        lambda: dict,
    ),
    _RegistryEntry(
        "service/control-hello-2.7.0.schema.json",
        "control-hello",
        "2.7.0",
        "request_result",
        "local-control",
        lambda: __import__("finishup.ports.control", fromlist=["ControlRequest"]).ControlRequest,
    ),
    _RegistryEntry(
        "service/control-hello-result-2.7.0.schema.json",
        "control-hello-result",
        "2.7.0",
        "request_result",
        "local-control",
        lambda: __import__("finishup.ports.control", fromlist=["ControlResult"]).ControlResult,
    ),
    _RegistryEntry(
        "service/control-request-2.7.0.schema.json",
        "control-request",
        "2.7.0",
        "request_result",
        "local-control",
        lambda: __import__("finishup.ports.control", fromlist=["ControlRequest"]).ControlRequest,
    ),
    _RegistryEntry(
        "service/control-result-2.7.0.schema.json",
        "control-result",
        "2.7.0",
        "request_result",
        "local-control",
        lambda: __import__("finishup.ports.control", fromlist=["ControlResult"]).ControlResult,
    ),
    _RegistryEntry(
        "service/control-hello-2.8.0.schema.json",
        "control-hello",
        "2.8.0",
        "request_result",
        "local-control",
        lambda: __import__("finishup.ports.control", fromlist=["ControlRequest"]).ControlRequest,
    ),
    _RegistryEntry(
        "service/control-hello-result-2.8.0.schema.json",
        "control-hello-result",
        "2.8.0",
        "request_result",
        "local-control",
        lambda: __import__("finishup.ports.control", fromlist=["ControlResult"]).ControlResult,
    ),
    _RegistryEntry(
        "service/control-request-2.8.0.schema.json",
        "control-request",
        "2.8.0",
        "request_result",
        "local-control",
        lambda: __import__("finishup.ports.control", fromlist=["ControlRequest"]).ControlRequest,
    ),
    _RegistryEntry(
        "service/control-result-2.8.0.schema.json",
        "control-result",
        "2.8.0",
        "request_result",
        "local-control",
        lambda: __import__("finishup.ports.control", fromlist=["ControlResult"]).ControlResult,
    ),
    _RegistryEntry(
        "service/control-hello-2.9.0.schema.json",
        "control-hello",
        "2.9.0",
        "request_result",
        "local-control",
        lambda: __import__("finishup.ports.control", fromlist=["ControlRequest"]).ControlRequest,
    ),
    _RegistryEntry(
        "service/control-hello-result-2.9.0.schema.json",
        "control-hello-result",
        "2.9.0",
        "request_result",
        "local-control",
        lambda: __import__("finishup.ports.control", fromlist=["ControlResult"]).ControlResult,
    ),
    _RegistryEntry(
        "service/control-request-2.9.0.schema.json",
        "control-request",
        "2.9.0",
        "request_result",
        "local-control",
        lambda: __import__("finishup.ports.control", fromlist=["ControlRequest"]).ControlRequest,
    ),
    _RegistryEntry(
        "service/control-result-2.9.0.schema.json",
        "control-result",
        "2.9.0",
        "request_result",
        "local-control",
        lambda: __import__("finishup.ports.control", fromlist=["ControlResult"]).ControlResult,
    ),
    _RegistryEntry(
        "service/isolation-report-1.0.0.schema.json",
        "isolation-report",
        "1.0.0",
        "request_result",
        "service-status",
        lambda: (
            __import__(
                "finishup.protocol.isolation_report", fromlist=["IsolationReportContract"]
            ).IsolationReportContract
        ),
    ),
    _RegistryEntry(
        "service/service-status-1.0.0.schema.json",
        "service-status",
        "1.0.0",
        "request_result",
        "service-status",
        lambda: __import__("finishup.ports.control", fromlist=["ServiceStatus"]).ServiceStatus,
    ),
    _RegistryEntry(
        "version/version-manifest-1.0.0.schema.json",
        "version-manifest",
        "1.0.0",
        "version_manifest",
        "version-report",
        None,
    ),
    _RegistryEntry(
        "version/version-manifest-2.0.0.schema.json",
        "version-manifest",
        "2.0.0",
        "version_manifest",
        "version-report",
        lambda: __import__("finishup.version", fromlist=["VersionManifest"]).VersionManifest,
    ),
    _RegistryEntry(
        "version/version-manifest-2.1.0.schema.json",
        "version-manifest",
        "2.1.0",
        "version_manifest",
        "version-report",
        lambda: __import__("finishup.version", fromlist=["VersionManifest"]).VersionManifest,
    ),
    _RegistryEntry(
        "version/version-manifest-2.2.0.schema.json",
        "version-manifest",
        "2.2.0",
        "version_manifest",
        "version-report",
        lambda: __import__("finishup.version", fromlist=["VersionManifest"]).VersionManifest,
    ),
    _RegistryEntry(
        "version/version-manifest-2.2.1.schema.json",
        "version-manifest",
        "2.2.1",
        "version_manifest",
        "version-report",
        lambda: __import__("finishup.version", fromlist=["VersionManifest"]).VersionManifest,
    ),
    _RegistryEntry(
        "version/version-manifest-2.2.2.schema.json",
        "version-manifest",
        "2.2.2",
        "version_manifest",
        "version-report",
        lambda: __import__("finishup.version", fromlist=["VersionManifest"]).VersionManifest,
    ),
    _RegistryEntry(
        "version/version-manifest-2.2.3.schema.json",
        "version-manifest",
        "2.2.3",
        "version_manifest",
        "version-report",
        lambda: __import__("finishup.version", fromlist=["VersionManifest"]).VersionManifest,
    ),
    _RegistryEntry(
        "version/version-manifest-2.2.4.schema.json",
        "version-manifest",
        "2.2.4",
        "version_manifest",
        "version-report",
        lambda: __import__("finishup.version", fromlist=["VersionManifest"]).VersionManifest,
    ),
    _RegistryEntry(
        "version/version-manifest-2.3.0.schema.json",
        "version-manifest",
        "2.3.0",
        "version_manifest",
        "version-report",
        lambda: __import__("finishup.version", fromlist=["VersionManifest"]).VersionManifest,
    ),
)


# These paths were introduced in the current protocol wave and are derived by this generator
# from the owning models/templates.  The other legacy ``loader=None`` entries are deliberately
# checked from their reviewed bytes only: their source model is not available to this tool and
# regenerating them would silently rewrite frozen history.
_BUILDER_OWNED_SCHEMA_PATHS: Final[frozenset[str]] = frozenset(
    {
        "integrations/ai-status-1.0.0.schema.json",
        # Role- and directory-bearing obligations (issue #1002).
        "events/obligation-published-1.1.0.schema.json",
        # The conversation review-mode switch (ADR-049).
        "events/decision-recorded-1.1.0.schema.json",
        # The task-statement contracts (issue #908).
        "events/plan-published-1.1.0.schema.json",
        "events/plan-revised-1.1.0.schema.json",
        "events/session-resumed-1.2.0.schema.json",
        "privacy/outbound-case-1.2.0.schema.json",
        "privacy/privacy-policy-1.2.0.schema.json",
        # The sized reviewer exchange bound (#1118).
        "privacy/privacy-policy-1.3.0.schema.json",
        "events/check-recorded-1.3.0.schema.json",
        "events/check-recorded-1.4.0.schema.json",
        "events/check-recorded-1.5.0.schema.json",
        "events/check-recorded-1.6.0.schema.json",
        "events/finding-recorded-1.4.0.schema.json",
        "findings/provider-judgment-1.1.0.schema.json",
        "findings/provider-judgment-1.2.0.schema.json",
        "findings/reviewer-reply-1.0.0.schema.json",
        "consent/status-7.0.0.schema.json",
        "consent/review-result-7.0.0.schema.json",
        "consent/prepare-result-7.0.0.schema.json",
        "consent/pending-agent-7.0.0.schema.json",
        "consent/catalog-7.0.0.schema.json",
        "common/lineage-acceptance-1.0.0.schema.json",
        "common/lineage-origin-1.0.0.schema.json",
        "common/session-health-1.0.0.schema.json",
        "common/work-state-1.0.0.schema.json",
        "events/child-accepted-1.0.0.schema.json",
        "events/child-dependencies-recorded-1.0.0.schema.json",
        "events/child-rejected-1.0.0.schema.json",
        "events/child-written-off-1.0.0.schema.json",
        "events/coordination-context-recorded-1.0.0.schema.json",
        "events/coordination-disposition-recorded-1.0.0.schema.json",
        "events/coordination-obligation-declared-1.0.0.schema.json",
        "events/delegation-cancelled-1.0.0.schema.json",
        "events/delegation-declared-1.0.0.schema.json",
        "events/event-draft-1.2.0.schema.json",
        "events/finding-recorded-1.3.0.schema.json",
        "events/opaque-unknown-event-draft-1.2.0.schema.json",
        "events/response-recorded-1.1.0.schema.json",
        "privacy/outbound-case-1.2.0.schema.json",
        "events/session-opened-1.2.0.schema.json",
        "events/work-abandoned-1.0.0.schema.json",
        "events/work-cancelled-1.0.0.schema.json",
        "events/work-closed-1.0.0.schema.json",
        "events/work-written-off-1.0.0.schema.json",
        "operations/check-result-1.3.0.schema.json",
        "operations/check-result-1.4.0.schema.json",
        "operations/check-result-1.5.0.schema.json",
        "operations/check-result-1.6.0.schema.json",
        "config/yoetz-config-1.3.0.schema.json",
        "operations/check-request-1.1.0.schema.json",
        "operations/publish-work-request-1.2.0.schema.json",
        "operations/receipt-result-1.3.0.schema.json",
        "operations/respond-request-1.1.0.schema.json",
        "operations/respond-result-1.1.0.schema.json",
        "operations/publish-work-result-1.1.0.schema.json",
        "operations/start-request-1.1.0.schema.json",
        "operations/start-result-1.1.0.schema.json",
        "operations/status-request-1.2.0.schema.json",
        "operations/status-result-1.4.0.schema.json",
        "operations/read-guidance-request-1.1.0.schema.json",
        "operations/read-guidance-result-1.1.0.schema.json",
        "observations/routine-read-summary-1.0.0.schema.json",
        "receipts/receipt-document-1.3.0.schema.json",
        "findings/finding-1.3.0.schema.json",
        "findings/finding-1.4.0.schema.json",
        "service/control-hello-2.7.0.schema.json",
        "service/control-hello-result-2.7.0.schema.json",
        "service/control-request-2.7.0.schema.json",
        "service/control-result-2.7.0.schema.json",
        "service/control-hello-2.8.0.schema.json",
        "service/control-hello-result-2.8.0.schema.json",
        "service/control-request-2.8.0.schema.json",
        "service/control-result-2.8.0.schema.json",
        "service/control-hello-2.9.0.schema.json",
        "service/control-hello-result-2.9.0.schema.json",
        "service/control-request-2.9.0.schema.json",
        "service/control-result-2.9.0.schema.json",
    }
)


# --------------------------------------------------------------------------
# Normalization
# --------------------------------------------------------------------------


def _rename_defs(raw: dict[str, object]) -> dict[str, object]:
    """Strip the framework ``Model``/``Payload`` suffix from generated ``$defs`` anchors."""

    defs = raw.get("$defs")
    if not isinstance(defs, dict):
        return raw

    rename: dict[str, str] = {}
    for key in cast(dict[str, object], defs):
        new_key = key
        for suffix in ("Model", "Payload"):
            if new_key.endswith(suffix) and len(new_key) > len(suffix):
                new_key = new_key[: -len(suffix)]
        rename[f"#/$defs/{key}"] = f"#/$defs/{new_key}"

    def _walk(node: object) -> object:
        if isinstance(node, dict):
            result: dict[str, object] = {}
            for key, value in cast(dict[str, object], node).items():
                if key == "$ref" and isinstance(value, str) and value in rename:
                    result[key] = rename[value]
                else:
                    result[key] = _walk(value)
            return result
        if isinstance(node, list):
            return [_walk(item) for item in cast(list[object], node)]
        return node

    renamed = cast(dict[str, object], _walk(raw))
    new_defs: dict[str, object] = {}
    for key, value in cast(dict[str, object], defs).items():
        target = rename[f"#/$defs/{key}"].removeprefix("#/$defs/")
        new_defs[target] = _walk(value)
    renamed["$defs"] = new_defs
    return renamed


def _sort_lists(node: object) -> object:
    """Sort ``required`` and ``enum`` value lists by ASCII byte order, recursively."""

    if isinstance(node, dict):
        result: dict[str, object] = {}
        mapping = cast(dict[str, object], node)
        for key, value in mapping.items():
            if key == "required" and isinstance(value, list):
                result[key] = sorted(cast(list[str], value), key=lambda item: item.encode("utf-8"))
            elif (
                key == "enum"
                and isinstance(value, list)
                and all(isinstance(item, str) for item in cast(list[object], value))
            ):
                result[key] = sorted(cast(list[str], value), key=lambda item: item.encode("utf-8"))
            else:
                result[key] = _sort_lists(cast(object, value))
        return result
    if isinstance(node, list):
        return [_sort_lists(item) for item in cast(list[object], node)]
    return node


def _enforce_closed_objects(node: object) -> object:
    """Set ``additionalProperties: false`` on every object schema that declares ``properties``."""

    if isinstance(node, dict):
        mapping = cast(dict[str, object], node)
        result = {key: _enforce_closed_objects(value) for key, value in mapping.items()}
        if (
            result.get("type") == "object"
            and "properties" in result
            and "additionalProperties" not in result
        ):
            result["additionalProperties"] = False
        return result
    if isinstance(node, list):
        return [_enforce_closed_objects(item) for item in cast(list[object], node)]
    return node


def _strip_framework_metadata(node: object) -> object:
    """Remove pydantic-internal keys that are not part of the frozen public contract."""

    forbidden = {"$comment"}
    if isinstance(node, dict):
        mapping = cast(dict[str, object], node)
        return {
            key: _strip_framework_metadata(value)
            for key, value in mapping.items()
            if key not in forbidden
        }
    if isinstance(node, list):
        return [_strip_framework_metadata(item) for item in cast(list[object], node)]
    return node


def _normalize(raw: dict[str, object], entry: _RegistryEntry) -> dict[str, JsonValue]:
    working = _rename_defs(raw)
    working = _strip_framework_metadata(working)
    working = _enforce_closed_objects(working)
    working = _sort_lists(working)

    document = cast(dict[str, object], working)
    document.pop("title", None)
    document["$schema"] = _DRAFT_2020_12
    document["$id"] = SCHEMA_NAMESPACE + entry.relative_path
    ordered: dict[str, object] = {"$id": document.pop("$id"), "$schema": document.pop("$schema")}
    ordered.update(document)
    ordered["title"] = entry.schema_name
    return cast(dict[str, JsonValue], ordered)


# --------------------------------------------------------------------------
# Public surface
# --------------------------------------------------------------------------


def _load_disk_document(entry: _RegistryEntry, schema_root: Path) -> SchemaDocument:
    """Load one registry-owned schema document from reviewed on-disk bytes."""

    candidate = schema_root / entry.relative_path
    if candidate.is_symlink() or not candidate.is_file():
        raise SchemaGenerationError("schema_missing", entries=(entry.relative_path,))
    try:
        schema_bytes = candidate.read_bytes()
        parsed = cast(object, json.loads(schema_bytes.decode("utf-8")))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SchemaGenerationError("schema_unreadable", entries=(entry.relative_path,)) from exc
    if not isinstance(parsed, dict):
        raise SchemaGenerationError("schema_invalid", entries=(entry.relative_path,))
    normalized = cast(dict[str, JsonValue], parsed)
    schema_id = cast(str, normalized.get("$id", ""))
    expected_id = SCHEMA_NAMESPACE + entry.relative_path
    if schema_id != expected_id:
        raise SchemaGenerationError("schema_id_mismatch", entries=(entry.relative_path,))
    if canonical_encode(cast(JsonValue, normalized)) != schema_bytes:
        raise SchemaGenerationError("schema_bytes_not_canonical", entries=(entry.relative_path,))
    return SchemaDocument(
        schema_kind=entry.schema_kind,
        artifact_role=entry.artifact_role,
        schema_name=entry.schema_name,
        schema_version=entry.schema_version,
        schema_id=schema_id,
        relative_path=entry.relative_path,
        canonical_digest=canonical_digest_hex(schema_bytes),
        schema_bytes=schema_bytes,
        json_schema=normalized,
    )


def _result_delivery_schema(entry: _RegistryEntry) -> dict[str, JsonValue]:
    """Add a presentation branch while retaining every released result shape verbatim."""
    predecessors = {
        "check-result": "check-result-1.6.0",
        "receipt-result": "receipt-result-1.3.0",
        "status-result": "status-result-1.4.0",
        "status-request": "status-request-1.2.0",
    }
    document = _load_versioned_template(
        entry, "operations/" + predecessors[entry.schema_name] + ".schema.json"
    )
    if entry.schema_name == "status-request":
        properties = cast(dict[str, JsonValue], document["properties"])
        properties["delivery"] = {"enum": ["complete", "paged"], "type": "string"}
        properties["delivery_cursor"] = {
            "type": "string",
            "minLength": 1,
            "maxLength": 4096,
            "pattern": "^[A-Za-z0-9_.-]+$",
        }
        rules = cast(list[JsonValue], document.setdefault("allOf", []))
        rules.append(
            {
                "if": {"required": ["delivery_cursor"]},
                "then": {
                    "properties": {"view": {"const": "compact"}},
                    "not": {
                        "anyOf": [
                            {"required": [name]}
                            for name in (
                                "cursor",
                                "filter",
                                "at_frontier",
                                "project_id",
                                "task_id",
                                "correlation_id",
                            )
                        ]
                    },
                },
            }
        )
    else:
        from finishup.protocol.models import DeliveryPageModel

        page = DeliveryPageModel.model_json_schema()
        page_defs = cast(dict[str, JsonValue], page.pop("$defs", {}))
        # Pydantic emits plain strings for BeforeValidator-backed wire types. Point the page's
        # identities, digests, frontier and disclosure receipt at the shared definitions the
        # sibling branches use, so the schema rejects what DeliveryPageModel rejects.
        for name in ("DataCategory", "FrontierModel", "PrivacyProjectionModel"):
            del page_defs[name]
        defs = cast(dict[str, JsonValue], document["$defs"])
        if any(name in defs for name in page_defs) or not {
            "digest",
            "request_id",
            "session_id",
            "task_id",
        } <= set(defs):
            raise SchemaGenerationError(
                "delivery_page_definitions_invalid", entries=(entry.relative_path,)
            )
        defs.update(page_defs)
        defs.setdefault("writer_id", _control_id_schema("writer_id"))
        properties = cast(dict[str, JsonValue], page["properties"])
        for name, target in (
            ("request_id", "request_id"),
            ("source_request_id", "request_id"),
            ("task_id", "task_id"),
            ("session_id", "session_id"),
            ("writer_id", "writer_id"),
            ("source_digest", "digest"),
        ):
            properties[name] = {"$ref": "#/$defs/" + target}
        properties["result_frontier"] = {
            "$ref": SCHEMA_NAMESPACE + "common/frontier-1.0.0.schema.json"
        }
        properties["privacy_projection"] = {
            "$ref": SCHEMA_NAMESPACE + "common/operation-result-1.0.0.schema.json"
            "#/$defs/privacy_projection"
        }
        fragment = cast(dict[str, JsonValue], defs["DeliveryFragmentModel"])
        cast(dict[str, JsonValue], fragment["properties"])["digest"] = {"$ref": "#/$defs/digest"}
        defs["delivery_page"] = cast(JsonValue, page)
        cast(list[JsonValue], document["oneOf"]).append({"$ref": "#/$defs/delivery_page"})
    return document


def build_schema_documents(
    *,
    schema_root: Path | None = None,
    entries: tuple[_RegistryEntry, ...] = _REGISTRY,
) -> tuple[SchemaDocument, ...]:
    """Build the ordered schema document set from the frozen registry.

    - ``schema_root`` set (``--check``): load every registry path from disk and validate. This covers
      hand-maintained ``loader=None`` entries and avoids false drift when the generator's Pydantic
      projection differs from already-reviewed committed bytes.
    - ``schema_root`` omitted (``--write``): introspect loader-backed types only; ``loader=None``
      entries fail closed with ``owning_type_not_yet_available`` (never fabricate them).
    """

    _install_type_shims()

    if schema_root is not None:
        seen_paths: set[str] = set()
        seen_ids: set[str] = set()
        documents: list[SchemaDocument] = []
        for entry in entries:
            if entry.relative_path in seen_paths:
                raise SchemaGenerationError("duplicate_path", entries=(entry.relative_path,))
            seen_paths.add(entry.relative_path)
            document = _load_disk_document(entry, schema_root)
            if document.schema_id in seen_ids:
                raise SchemaGenerationError("duplicate_schema_id", entries=(document.schema_id,))
            seen_ids.add(document.schema_id)
            documents.append(document)
        return tuple(sorted(documents, key=lambda doc: doc.relative_path.encode("utf-8")))

    pending = tuple(entry.relative_path for entry in entries if entry.loader is None)
    if pending:
        raise SchemaGenerationError("owning_type_not_yet_available", entries=pending)

    seen_paths = set()
    seen_ids = set()
    documents = []

    for entry in entries:
        if entry.relative_path in seen_paths:
            raise SchemaGenerationError("duplicate_path", entries=(entry.relative_path,))
        seen_paths.add(entry.relative_path)

        assert entry.loader is not None  # narrowed by the pending-check above
        if entry.relative_path in {
            "common/lineage-acceptance-1.0.0.schema.json",
            "common/lineage-origin-1.0.0.schema.json",
            "common/session-health-1.0.0.schema.json",
            "common/work-state-1.0.0.schema.json",
        }:
            normalized = _lineage_vocabulary_schema(entry)
        elif entry.relative_path in {
            "consent/catalog-7.0.0.schema.json",
            "privacy/privacy-policy-1.0.0.schema.json",
            "config/yoetz-config-1.0.0.schema.json",
            "config/yoetz-config-1.1.0.schema.json",
            "config/yoetz-config-1.2.0.schema.json",
            "events/check-recorded-1.0.0.schema.json",
            "events/finding-recorded-1.0.0.schema.json",
            "events/result-recorded-1.0.0.schema.json",
            "findings/finding-1.0.0.schema.json",
            "findings/provider-judgment-1.0.0.schema.json",
            "findings/semantic-provenance-1.0.0.schema.json",
            "operations/check-result-1.0.0.schema.json",
            "operations/receipt-result-1.0.0.schema.json",
        }:
            # Released contracts whose owning model has since moved on stay byte-frozen.
            normalized = _frozen_schema(entry)
        elif entry.relative_path == "observations/routine-read-summary-1.0.0.schema.json":
            normalized = _routine_read_summary_schema(entry)
        elif entry.relative_path in {
            "events/plan-published-1.0.0.schema.json",
            "events/plan-revised-1.0.0.schema.json",
        }:
            normalized = _plan_payload_schema(entry)
        elif entry.relative_path == "events/result-recorded-1.1.0.schema.json":
            normalized = _result_recorded_v1_1_schema(entry)
        elif entry.relative_path == "events/event-draft-1.0.0.schema.json":
            normalized = _frozen_schema(entry)
        elif entry.relative_path == "events/event-draft-1.1.0.schema.json":
            normalized = _event_draft_v1_1_schema(entry)
        elif entry.relative_path == "events/event-draft-1.2.0.schema.json":
            normalized = _event_draft_v1_2_schema(entry)
        elif entry.relative_path == "events/check-recorded-1.1.0.schema.json":
            normalized = _check_recorded_v1_1_schema(entry)
        elif entry.relative_path == "events/check-recorded-1.3.0.schema.json":
            normalized = _check_recorded_v1_3_schema(entry)
        elif entry.relative_path == "events/check-recorded-1.4.0.schema.json":
            normalized = _check_recorded_v1_4_schema(entry)
        elif entry.relative_path == "events/check-recorded-1.5.0.schema.json":
            normalized = _check_recorded_v1_5_schema(entry)
        elif entry.relative_path == "events/check-recorded-1.6.0.schema.json":
            normalized = _check_recorded_v1_6_schema(entry)
        elif entry.relative_path == "findings/provider-judgment-1.1.0.schema.json":
            normalized = _provider_judgment_v1_1_schema(entry)
        elif entry.relative_path == "findings/provider-judgment-1.2.0.schema.json":
            normalized = _provider_judgment_v1_2_schema(entry)
        elif entry.relative_path == "findings/reviewer-reply-1.0.0.schema.json":
            normalized = _reviewer_reply_schema(entry)
        elif entry.relative_path == "events/check-recorded-1.2.0.schema.json":
            normalized = _simple_versioned_schema(
                entry,
                "events/check-recorded-1.1.0.schema.json",
                {"semantic-provenance-1.1.0": "semantic-provenance-1.2.0"},
            )
        elif entry.relative_path == "events/finding-recorded-1.1.0.schema.json":
            normalized = _simple_versioned_schema(
                entry,
                "events/finding-recorded-1.0.0.schema.json",
                {"finding-1.0.0": "finding-1.1.0"},
            )
        elif entry.relative_path == "events/finding-recorded-1.3.0.schema.json":
            normalized = _finding_recorded_v1_3_schema(entry)
        elif entry.relative_path == "events/finding-recorded-1.4.0.schema.json":
            normalized = _finding_recorded_v1_4_schema(entry)
        elif entry.relative_path in {
            "events/evidence-recorded-1.1.0.schema.json",
            "events/evidence-recorded-1.2.0.schema.json",
        }:
            normalized = _evidence_payload_schema(entry)
        elif entry.relative_path == "events/claim-recorded-1.1.0.schema.json":
            normalized = _claim_payload_schema(entry)
        elif entry.relative_path == "events/response-recorded-1.0.0.schema.json":
            normalized = _response_recorded_schema(entry)
        elif entry.relative_path == "events/response-recorded-1.1.0.schema.json":
            normalized = _response_recorded_v1_1_schema(entry)
        elif entry.relative_path in {
            "events/child-accepted-1.0.0.schema.json",
            "events/child-dependencies-recorded-1.0.0.schema.json",
            "events/child-rejected-1.0.0.schema.json",
            "events/child-written-off-1.0.0.schema.json",
            "events/delegation-cancelled-1.0.0.schema.json",
            "events/delegation-declared-1.0.0.schema.json",
            "events/work-abandoned-1.0.0.schema.json",
            "events/work-cancelled-1.0.0.schema.json",
            "events/work-closed-1.0.0.schema.json",
            "events/work-written-off-1.0.0.schema.json",
        }:
            normalized = _lineage_event_schema(entry)
        elif entry.relative_path in {
            "events/coordination-context-recorded-1.0.0.schema.json",
            "events/coordination-obligation-declared-1.0.0.schema.json",
            "events/coordination-disposition-recorded-1.0.0.schema.json",
        }:
            normalized = _coordination_event_schema(entry)
        elif entry.relative_path == "events/session-opened-1.2.0.schema.json":
            normalized = _lineage_session_opened_schema(entry)
        elif entry.relative_path == "events/opaque-unknown-event-draft-1.0.0.schema.json":
            normalized = _frozen_schema(entry)
        elif entry.relative_path == "events/opaque-unknown-event-draft-1.1.0.schema.json":
            normalized = _opaque_unknown_event_v1_1_schema(entry)
        elif entry.relative_path == "events/opaque-unknown-event-draft-1.2.0.schema.json":
            normalized = _opaque_unknown_event_v1_2_schema(entry)
        elif entry.relative_path in {
            "service/control-hello-2.7.0.schema.json",
            "service/control-hello-result-2.7.0.schema.json",
            "service/control-request-2.7.0.schema.json",
            "service/control-result-2.7.0.schema.json",
        }:
            normalized = _control_v2_7_schema(entry)
        elif entry.relative_path in {
            "service/control-hello-2.8.0.schema.json",
            "service/control-hello-result-2.8.0.schema.json",
            "service/control-request-2.8.0.schema.json",
            "service/control-result-2.8.0.schema.json",
        }:
            normalized = _control_v2_8_schema(entry)
        elif entry.relative_path in {
            "service/control-hello-2.9.0.schema.json",
            "service/control-hello-result-2.9.0.schema.json",
            "service/control-request-2.9.0.schema.json",
            "service/control-result-2.9.0.schema.json",
        }:
            normalized = _control_v2_9_schema(entry)
        elif entry.relative_path == "operations/publish-work-request-1.1.0.schema.json":
            normalized = _publish_work_request_schema(entry)
        elif entry.relative_path == "operations/publish-work-request-1.2.0.schema.json":
            normalized = _publish_work_request_v1_2_schema(entry)
        elif entry.relative_path == "findings/runtime-attempt-evidence-1.0.0.schema.json":
            normalized = _runtime_attempt_evidence_schema(entry)
        elif entry.relative_path == "findings/runtime-attempt-evidence-1.1.0.schema.json":
            normalized = _runtime_attempt_evidence_schema(entry)
        elif entry.relative_path == "findings/semantic-provenance-1.1.0.schema.json":
            normalized = _semantic_provenance_v1_1_schema(entry)
        elif entry.relative_path == "findings/semantic-provenance-1.2.0.schema.json":
            normalized = _semantic_provenance_v1_2_schema(entry)
        elif entry.relative_path == "findings/finding-1.1.0.schema.json":
            normalized = _simple_versioned_schema(
                entry,
                "findings/finding-1.0.0.schema.json",
                {"semantic-provenance-1.0.0": "semantic-provenance-1.1.0"},
            )
        elif entry.relative_path == "findings/finding-1.3.0.schema.json":
            normalized = _finding_v1_3_schema(entry)
        elif entry.relative_path == "findings/finding-1.4.0.schema.json":
            normalized = _finding_v1_4_schema(entry)
        elif entry.relative_path == "operations/check-request-1.1.0.schema.json":
            normalized = _check_request_v1_1_schema(entry)
        elif entry.relative_path == "operations/check-result-1.1.0.schema.json":
            normalized = _check_result_v1_1_schema(entry)
        elif entry.relative_path == "operations/check-result-1.3.0.schema.json":
            normalized = _check_result_v1_3_schema(entry)
        elif entry.relative_path == "operations/check-result-1.4.0.schema.json":
            normalized = _check_result_v1_4_schema(entry)
        elif entry.relative_path == "operations/check-result-1.5.0.schema.json":
            normalized = _check_result_v1_5_schema(entry)
        elif entry.relative_path in {
            "operations/check-result-1.7.0.schema.json",
            "operations/receipt-result-1.4.0.schema.json",
            "operations/status-result-1.5.0.schema.json",
            "operations/status-request-1.3.0.schema.json",
        }:
            normalized = _result_delivery_schema(entry)
        elif entry.relative_path == "operations/check-result-1.6.0.schema.json":
            normalized = _check_result_v1_6_schema(entry)
        elif entry.relative_path == "operations/receipt-result-1.1.0.schema.json":
            normalized = _simple_versioned_schema(
                entry,
                "operations/receipt-result-1.0.0.schema.json",
                {"receipt-document-1.0.0": "receipt-document-1.1.0"},
            )
        elif entry.relative_path == "operations/receipt-result-1.3.0.schema.json":
            normalized = _receipt_result_v1_3_schema(entry)
        elif entry.relative_path == "operations/start-result-1.0.0.schema.json":
            normalized = _start_result_schema(entry)
        elif entry.relative_path == "operations/start-result-1.1.0.schema.json":
            normalized = _start_result_v1_1_schema(entry)
        elif entry.relative_path == "operations/start-request-1.1.0.schema.json":
            normalized = _start_request_v1_1_schema(entry)
        elif entry.relative_path == "operations/read-guidance-result-1.1.0.schema.json":
            normalized = _read_guidance_result_schema(entry)
        elif entry.relative_path == "operations/read-guidance-request-1.1.0.schema.json":
            normalized = _read_guidance_request_schema(entry)
        elif entry.relative_path == "operations/publish-work-result-1.0.0.schema.json":
            normalized = _publish_work_result_schema(entry)
        elif entry.relative_path == "operations/respond-request-1.0.0.schema.json":
            normalized = _respond_request_schema(entry)
        elif entry.relative_path == "operations/respond-result-1.0.0.schema.json":
            normalized = _respond_result_schema(entry)
        elif entry.relative_path == "operations/respond-request-1.1.0.schema.json":
            normalized = _respond_request_v1_1_schema(entry)
        elif entry.relative_path == "operations/respond-result-1.1.0.schema.json":
            normalized = _respond_result_v1_1_schema(entry)
        elif entry.relative_path == "operations/publish-work-result-1.1.0.schema.json":
            normalized = _publish_work_result_v1_1_schema(entry)
        elif entry.relative_path in {
            "operations/status-request-1.0.0.schema.json",
            "operations/status-request-1.1.0.schema.json",
        }:
            normalized = _status_request_schema(entry)
        elif entry.relative_path == "operations/status-request-1.2.0.schema.json":
            normalized = _status_request_v1_2_schema(entry)
        elif entry.relative_path in {
            "operations/status-result-1.0.0.schema.json",
            "operations/status-result-1.1.0.schema.json",
        }:
            normalized = _status_result_schema(entry)
        elif entry.relative_path == "operations/status-result-1.2.0.schema.json":
            normalized = _simple_versioned_schema(
                entry,
                "operations/status-result-1.1.0.schema.json",
                {"semantic-provenance-1.0.0": "semantic-provenance-1.1.0"},
            )
        elif entry.relative_path == "operations/status-result-1.4.0.schema.json":
            normalized = _status_result_v1_4_schema(entry)
        elif entry.relative_path == "receipts/receipt-document-1.0.0.schema.json":
            normalized = _receipt_document_schema(entry)
        elif entry.relative_path == "receipts/receipt-document-1.1.0.schema.json":
            normalized = _simple_versioned_schema(
                entry,
                "receipts/receipt-document-1.0.0.schema.json",
                {
                    "finding-1.0.0": "finding-1.1.0",
                    "semantic-provenance-1.0.0": "semantic-provenance-1.1.0",
                },
            )
        elif entry.relative_path == "receipts/receipt-document-1.3.0.schema.json":
            normalized = _receipt_document_v1_3_schema(entry)
        elif entry.relative_path in {
            "version/version-manifest-2.0.0.schema.json",
            "version/version-manifest-2.1.0.schema.json",
            "version/version-manifest-2.2.0.schema.json",
            "version/version-manifest-2.2.1.schema.json",
            "version/version-manifest-2.2.2.schema.json",
            "version/version-manifest-2.2.3.schema.json",
            "version/version-manifest-2.2.4.schema.json",
        }:
            normalized = _frozen_version_manifest_schema(entry)
        elif entry.relative_path == "version/version-manifest-2.3.0.schema.json":
            normalized = _version_manifest_schema(entry)
        elif entry.relative_path == "service/control-request-2.6.1.schema.json":
            normalized = _control_request_v2_6_1_schema(entry)
        elif entry.relative_path == "service/control-result-2.6.1.schema.json":
            normalized = _control_result_v2_6_1_schema(entry)
        elif entry.relative_path == "privacy/privacy-policy-1.1.0.schema.json":
            normalized = _privacy_policy_v1_1_schema(entry)
        elif entry.relative_path == "privacy/privacy-policy-1.2.0.schema.json":
            normalized = _privacy_policy_v1_2_schema(entry)
        elif entry.relative_path == "privacy/privacy-policy-1.3.0.schema.json":
            normalized = _privacy_policy_v1_3_schema(entry)
        elif entry.relative_path == "privacy/egress-receipt-1.1.0.schema.json":
            normalized = _egress_receipt_v1_1_schema(entry)
        elif entry.relative_path == "events/session-resumed-1.2.0.schema.json":
            normalized = _with_required_task_statement(
                entry, "events/session-resumed-1.1.0.schema.json"
            )
        elif entry.relative_path == "events/obligation-published-1.0.0.schema.json":
            # Released: the domain model now also admits 1.1.0 items, so never re-derive it.
            normalized = _frozen_schema(entry)
        elif entry.relative_path == "events/obligation-published-1.1.0.schema.json":
            normalized = _obligation_published_v1_1_schema(entry)
        elif entry.relative_path == "events/decision-recorded-1.0.0.schema.json":
            # Released: the domain model now also admits the 1.1.0 switch, so never re-derive it.
            normalized = _frozen_schema(entry)
        elif entry.relative_path == "events/decision-recorded-1.1.0.schema.json":
            normalized = _decision_recorded_v1_1_schema(entry)
        elif entry.relative_path == "events/plan-published-1.1.0.schema.json":
            normalized = _with_required_task_statement(
                entry, "events/plan-published-1.0.0.schema.json", title="Yoetz plan published"
            )
        elif entry.relative_path == "events/plan-revised-1.1.0.schema.json":
            normalized = _with_required_task_statement(
                entry, "events/plan-revised-1.0.0.schema.json", title="Yoetz plan revised"
            )
        elif entry.relative_path == "privacy/review-packet-row-2.0.0.schema.json":
            normalized = _review_packet_row_schema(entry)
        elif entry.relative_path == "privacy/outbound-case-1.1.0.schema.json":
            normalized = _outbound_case_schema(entry)
        elif entry.relative_path == "privacy/outbound-case-1.2.0.schema.json":
            normalized = _outbound_case_v1_2_schema(entry)
        else:
            try:
                python_type = entry.loader()
                raw_schema = TypeAdapter(python_type).json_schema()
            except Exception as exc:  # noqa: BLE001 - normalized into a bounded generator error
                raise SchemaGenerationError(
                    "model_introspection_failed", entries=(entry.relative_path,)
                ) from exc
            normalized = _normalize(cast(dict[str, object], raw_schema), entry)
        schema_id = cast(str, normalized["$id"])
        if schema_id in seen_ids:
            raise SchemaGenerationError("duplicate_schema_id", entries=(schema_id,))
        seen_ids.add(schema_id)

        rendered = render_schema(cast(Mapping[str, JsonValue], normalized))
        documents.append(
            SchemaDocument(
                schema_kind=entry.schema_kind,
                artifact_role=entry.artifact_role,
                schema_name=entry.schema_name,
                schema_version=entry.schema_version,
                schema_id=schema_id,
                relative_path=entry.relative_path,
                canonical_digest=canonical_digest_hex(rendered),
                schema_bytes=rendered,
                json_schema=cast(Mapping[str, JsonValue], normalized),
            )
        )

    return tuple(sorted(documents, key=lambda doc: doc.relative_path.encode("utf-8")))


def canonical_digest_hex(data: bytes) -> str:
    import hashlib

    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def validate_schema_document(document: SchemaDocument) -> None:
    """Recheck a generated document's dialect and FinishUP policy invariants."""

    if document.json_schema.get("$schema") != _DRAFT_2020_12:
        raise SchemaGenerationError("schema_draft_unsupported", entries=(document.relative_path,))
    expected_id = SCHEMA_NAMESPACE + document.relative_path
    if document.schema_id != expected_id or document.json_schema.get("$id") != expected_id:
        raise SchemaGenerationError("schema_id_mismatch", entries=(document.relative_path,))
    if canonical_encode(cast(JsonValue, document.json_schema)) != document.schema_bytes:
        raise SchemaGenerationError("schema_bytes_not_canonical", entries=(document.relative_path,))

    from jsonschema import Draft202012Validator
    from jsonschema.exceptions import SchemaError

    try:
        Draft202012Validator.check_schema(cast(dict[str, object], document.json_schema))
    except SchemaError as exc:
        raise SchemaGenerationError(
            "schema_metaschema_invalid", entries=(document.relative_path,)
        ) from exc


def render_schema(document: Mapping[str, JsonValue]) -> bytes:
    """Render a schema document to canonical compact UTF-8 bytes with no trailing newline."""

    return canonical_encode(cast(JsonValue, document))


def compare_tree(expected: tuple[SchemaDocument, ...], root: Path) -> SchemaDiff:
    """Compare generated documents against the on-disk reviewed schema tree, read-only."""

    expected_by_path = {document.relative_path: document for document in expected}
    missing: list[str] = []
    changed: list[str] = []

    for relative_path, document in sorted(expected_by_path.items()):
        candidate = root / relative_path
        if candidate.is_symlink() or not candidate.is_file():
            missing.append(relative_path)
            continue
        on_disk = candidate.read_bytes()
        if on_disk != document.schema_bytes:
            changed.append(relative_path)

    extra: list[str] = []
    if root.is_dir():
        for candidate in sorted(root.rglob("*.schema.json")):
            if candidate.is_symlink():
                continue
            relative = candidate.relative_to(root).as_posix()
            if relative not in expected_by_path:
                extra.append(relative)

    return SchemaDiff(missing=tuple(missing), extra=tuple(extra), changed=tuple(changed))


def write_tree(expected: tuple[SchemaDocument, ...], root: Path) -> None:
    """Atomically stage and replace only generator-owned schema files beneath ``root``."""

    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=root.parent, prefix=".generate-schemas-") as staging:
        staging_root = Path(staging)
        for document in expected:
            destination = staging_root / document.relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(document.schema_bytes)
            with open(destination, "rb") as handle:
                os.fsync(handle.fileno())

        for document in expected:
            source = staging_root / document.relative_path
            target = root / document.relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            os.replace(source, target)


def update_schema_manifest(documents: tuple[SchemaDocument, ...], root: Path) -> None:
    """Refresh reviewed byte identities for schemas regenerated by this tool."""

    manifest_path = root / "manifest.json"
    try:
        manifest = cast(dict[str, JsonValue], json.loads(manifest_path.read_bytes()))
        members = cast(list[JsonValue], manifest["members"])
    except (KeyError, OSError, TypeError, json.JSONDecodeError) as exc:
        raise SchemaGenerationError("schema_manifest_unreadable") from exc
    by_path = {
        cast(str, cast(dict[str, JsonValue], member)["path"]): cast(dict[str, JsonValue], member)
        for member in members
    }
    registry_by_path = {entry.relative_path: entry for entry in _REGISTRY}
    for document in documents:
        member = by_path.get(document.relative_path)
        if member is None:
            entry = registry_by_path[document.relative_path]
            assert entry.loader is not None
            owning_type = entry.loader()
            member = {
                "$id": document.schema_id,
                "artifact_role": document.artifact_role,
                "byte_length": len(document.schema_bytes),
                "media_type": _SCHEMA_MEDIA_TYPE,
                "owning_model": getattr(owning_type, "__name__", type(owning_type).__name__),
                "path": document.relative_path,
                "schema_kind": document.schema_kind,
                "schema_version": document.schema_version,
                "sha256": "sha256:" + hashlib.sha256(document.schema_bytes).hexdigest(),
            }
            members.append(cast(JsonValue, member))
            by_path[document.relative_path] = member
        member["byte_length"] = len(document.schema_bytes)
        member["sha256"] = "sha256:" + hashlib.sha256(document.schema_bytes).hexdigest()
    members.sort(key=lambda item: cast(str, cast(dict[str, JsonValue], item)["path"]).encode())
    manifest_path.write_bytes(canonical_encode(cast(JsonValue, manifest)))


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _default_schema_root() -> Path:
    return Path(__file__).resolve().parent.parent / "schemas"


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="generate_schemas.py",
        description="Generate and verify the reviewable public JSON Schema tree.",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="Verify schemas/ matches the registry.")
    mode.add_argument("--write", action="store_true", help="Regenerate schemas/ from the registry.")
    parser.add_argument(
        "--output-root",
        type=Path,
        default=None,
        help="Test-only: an explicit temporary output root instead of repository schemas/.",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="RELATIVE_PATH",
        help="With --write, regenerate only the named loader-backed registry path (repeatable).",
    )
    parser.add_argument(
        "--include-builder-owned",
        action="store_true",
        help="With --write, include the current builder-owned wave without rewriting frozen schemas.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    root = args.output_root.resolve() if args.output_root is not None else _default_schema_root()
    selected_entries = _REGISTRY
    if args.only or args.include_builder_owned:
        if args.check:
            parser.error("schema selection is supported only with --write")
        requested = frozenset(args.only) | (
            _BUILDER_OWNED_SCHEMA_PATHS if args.include_builder_owned else frozenset()
        )
        selected_entries = tuple(entry for entry in _REGISTRY if entry.relative_path in requested)
        missing = sorted(requested - {entry.relative_path for entry in selected_entries})
        if missing:
            parser.error(f"unknown schema registry path: {missing[0]}")

    try:
        # --check may load hand-maintained registry entries (loader=None) from disk.
        # --write still requires owning Python types and never fabricates those files.
        documents = build_schema_documents(
            schema_root=root if args.check else None,
            entries=selected_entries,
        )
        for document in documents:
            validate_schema_document(document)
    except SchemaGenerationError as exc:
        print(f"generate_schemas: FAIL ({exc.reason})", file=sys.stderr)
        for entry in exc.entries:
            print(f"  {entry}", file=sys.stderr)
        return 1

    if args.check:
        # ``schema_root`` mode intentionally treats legacy loader-less entries as reviewed
        # documents.  Rebuild only the current wave's owned paths as an additional guard so a
        # changed derivation cannot leave a stale source file while the disk-only check remains
        # green.  This subset is read-only and never rewrites manifests or schema files.
        builder_entries = tuple(
            entry
            for entry in selected_entries
            if entry.relative_path in _BUILDER_OWNED_SCHEMA_PATHS
        )
        if builder_entries:
            try:
                generated = build_schema_documents(entries=builder_entries)
                for document in generated:
                    validate_schema_document(document)
            except SchemaGenerationError as exc:
                print(f"generate_schemas: FAIL ({exc.reason})", file=sys.stderr)
                for entry in exc.entries:
                    print(f"  {entry}", file=sys.stderr)
                return 1
            generated_diff = compare_tree(generated, root)
            # ``compare_tree`` also reports every schema outside this deliberate subset as
            # ``extra``.  Those files are expected here because the subset is only the current
            # builder-owned wave, so only missing or changed owned paths are drift.
            if generated_diff.missing or generated_diff.changed:
                print("generate_schemas: FAIL (builder-owned drift detected)", file=sys.stderr)
                for relative_path in generated_diff.missing:
                    print(f"  missing {relative_path}", file=sys.stderr)
                for relative_path in generated_diff.changed:
                    print(f"  changed {relative_path}", file=sys.stderr)
                return 1
        diff = compare_tree(documents, root)
        if diff.is_clean:
            print(f"generate_schemas: PASS ({len(documents)} schema(s) match)")
            return 0
        print("generate_schemas: FAIL (drift detected)", file=sys.stderr)
        for relative_path in diff.missing:
            print(f"  missing {relative_path}", file=sys.stderr)
        for relative_path in diff.extra:
            print(f"  extra {relative_path}", file=sys.stderr)
        for relative_path in diff.changed:
            print(f"  changed {relative_path}", file=sys.stderr)
        return 1

    write_tree(documents, root)
    try:
        update_schema_manifest(documents, root)
    except SchemaGenerationError as exc:
        print(f"generate_schemas: FAIL ({exc.reason})", file=sys.stderr)
        for entry in exc.entries:
            print(f"  {entry}", file=sys.stderr)
        return 1
    if args.only or args.include_builder_owned:
        for document in documents:
            if (root / document.relative_path).read_bytes() != document.schema_bytes:
                print("generate_schemas: FAIL (post-write verification drift)", file=sys.stderr)
                return 1
        print(f"generate_schemas: WROTE ({len(documents)} schema(s))")
        return 0
    diff = compare_tree(documents, root)
    if not diff.is_clean:
        print("generate_schemas: FAIL (post-write verification drift)", file=sys.stderr)
        return 1
    print(f"generate_schemas: WROTE ({len(documents)} schema(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
