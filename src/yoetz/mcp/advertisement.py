"""Small, host-stable authoring schemas; never a request admission boundary."""

from __future__ import annotations

import json
from collections.abc import Mapping
from types import MappingProxyType
from typing import Final, cast

from yoetz.protocol.canonical import JsonValue
from yoetz.protocol.schemas import schema_document_for

ADVERTISED_INPUT_SCHEMA_MAX_BYTES: Final = 4_800
_TEMPLATES: Final = "yoetz://guidance/request-templates.md"
_METADATA: Final = frozenset({"title", "description", "examples"})


def _common_payload_hints() -> dict[str, JsonValue]:
    """Inline common field types/enums from their owning schemas, without a variant union.

    Fields stay optional here: which ones are required or forbidden depends on schema.name.
    Keep the payload open so other catalog variants can still travel through validating hosts.
    """

    hints: dict[str, JsonValue] = {}
    for family, fields in (
        ("plan-published", ("plan_version", "summary", "obligation_refs", "no_obligations_reason")),
        (
            "action-recorded",
            ("action_id", "action_kind", "description", "command", "attempted_items"),
        ),
        ("result-recorded", ("result_id", "outcome")),
    ):
        document = schema_document_for(family, "1.0.0").json_schema

        def shape(node: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
            ref = node.get("$ref")
            if isinstance(ref, str):
                if not ref.startswith("#/$defs/"):
                    raise RuntimeError("mcp_payload_hint_reference_invalid")
                definitions = cast(Mapping[str, JsonValue], document["$defs"])
                return shape(
                    cast(Mapping[str, JsonValue], definitions[ref.removeprefix("#/$defs/")])
                )
            result = {key: node[key] for key in ("type", "enum") if key in node}
            if "enum" in result:
                result["enum"] = list(cast(tuple[JsonValue, ...], result["enum"]))
            if "items" in node:
                result["items"] = shape(cast(Mapping[str, JsonValue], node["items"]))
            return result

        properties = cast(Mapping[str, JsonValue], document["properties"])
        for field in fields:
            hints[field] = shape(cast(Mapping[str, JsonValue], properties[field]))
    return hints


def compact_input_schema(name: str, schema: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
    """Project explicit authoring shapes below Codex's 5,000-byte rewrite threshold.

    Preserve fields, required lists, enums and inline unions, except publish_work's payload
    discrimination graph. That graph and the worked examples remain available to server-side
    repair hints and through read_guidance. Never use this projection to validate requests.
    """

    def project(value: JsonValue) -> JsonValue:
        if isinstance(value, Mapping):
            mapping = cast(Mapping[str, JsonValue], value)
            result: dict[str, JsonValue] = {}
            for key, child in mapping.items():
                if key in _METADATA or key == "$defs":
                    continue
                if key == "properties" and isinstance(child, Mapping):
                    # These keys are field names, not schema annotations.
                    result[key] = {
                        field: project(body)
                        for field, body in cast(Mapping[str, JsonValue], child).items()
                    }
                else:
                    result[key] = project(child)
            if result.get("type") == "string" and result.get("maxLength") == 19:
                # Exact int64 range regexes cost ~500 bytes each. The full catalog still owns
                # range admission; the advertised shape keeps canonical decimal syntax.
                result["pattern"] = "^(0|[1-9][0-9]*)$"
                result["description"] = "Canonical integer string, at most 9223372036854775807."
            return result
        if isinstance(value, tuple | list):
            return [
                project(child) for child in cast(tuple[JsonValue, ...] | list[JsonValue], value)
            ]
        return value

    # Remove only the event discrimination graph before traversing it. Keep the complete
    # envelope, all ordinary family names and its open payload object as the authoring surface.
    source = dict(schema)
    if name == "publish_work":
        properties = dict(cast(Mapping[str, JsonValue], source["properties"]))
        drafts = dict(cast(Mapping[str, JsonValue], properties["event_drafts"]))
        items = dict(cast(Mapping[str, JsonValue], drafts["items"]))
        items.pop("oneOf")
        drafts["items"] = items
        properties["event_drafts"] = drafts
        source["properties"] = properties

    result = cast(dict[str, JsonValue], project(source))
    if name != "read_guidance":
        result["description"] = (
            f"Compact authoring shape; server applies full validation. Use read_guidance uri={_TEMPLATES} "
            "for payload variants, field rules and complete request examples."
        )
    if name == "publish_work":
        properties = cast(dict[str, JsonValue], result["properties"])
        drafts = cast(dict[str, JsonValue], properties["event_drafts"])
        items = cast(dict[str, JsonValue], drafts["items"])
        fields = cast(dict[str, JsonValue], items["properties"])
        fields["payload"] = {
            "type": "object",
            "properties": _common_payload_hints(),
            "description": "Read request-templates.md for the exact schema.name/version payload before publishing.",
        }
    encoded = json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    if len(encoded) > ADVERTISED_INPUT_SCHEMA_MAX_BYTES:
        raise RuntimeError("mcp_advertised_input_schema_over_budget")
    return MappingProxyType(result)
