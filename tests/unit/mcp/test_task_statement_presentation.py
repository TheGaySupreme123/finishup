"""The advertised publish_work draft stays within budget and admits statement-bearing plans.

The MCP presentation exposes the statement-bearing plan_published/plan_revised 1.1.0 branches so a
parked review can receive its missing specification without replacing the session and writer that
own the original check request. An MCP agent can also provide the initial statement through
``start``.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import cast

from yoetz.mcp.descriptors import descriptor_for
from yoetz.protocol.canonical import JsonValue
from yoetz.protocol.schemas import validate_schema_instance

_STATEMENT = "Under Ascii, Style.Truncate returns plain text without tail."


def _schema_identities(node: JsonValue) -> Iterator[tuple[str, str]]:
    if isinstance(node, dict):
        properties = node.get("properties")
        if isinstance(properties, dict):
            schema = properties.get("schema")
            if isinstance(schema, dict):
                nested = schema.get("properties")
                if isinstance(nested, dict):
                    name = nested.get("name")
                    version = nested.get("version")
                    if isinstance(name, dict) and isinstance(version, dict):
                        const_name = name.get("const")
                        const_version = version.get("const")
                        if type(const_name) is str and type(const_version) is str:
                            yield const_name, const_version
        for value in node.values():
            yield from _schema_identities(value)
    elif isinstance(node, list):
        for value in node:
            yield from _schema_identities(value)


def test_statement_plans_and_the_start_field_are_advertised() -> None:
    publish = cast(JsonValue, dict(descriptor_for("publish_work").input_schema))
    identities = set(_schema_identities(publish))
    assert ("plan_published", "1.0.0") in identities
    assert ("plan_revised", "1.0.0") in identities
    assert ("plan_published", "1.1.0") in identities
    assert ("plan_revised", "1.1.0") in identities
    start = descriptor_for("start")
    assert "task_statement" in cast(dict[str, JsonValue], start.input_schema["properties"])
    assert "task_statement is the user's request verbatim" in start.description


def test_the_catalog_event_draft_still_admits_a_statement_bearing_revision() -> None:
    draft = cast(
        JsonValue,
        {
            "event_id": "evt_90800000-0000-4000-8000-000000000003",
            "schema": {"name": "plan_revised", "version": "1.1.0"},
            "occurred_at": "2026-09-30T12:00:01.000Z",
            "causal_parents": [],
            "payload": {
                "plan_version": 2,
                "supersedes_plan_version": 1,
                "reason": "The user amended the request.",
                "summary": "Agent plan",
                "obligation_changes": [],
                "no_obligations_reason": "single_atomic_change",
                "task_statement": _STATEMENT,
            },
            "artifact_refs": [],
            "evidence_refs": [],
        },
    )
    validate_schema_instance("event-draft", "1.2.0", draft)
