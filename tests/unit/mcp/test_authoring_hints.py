"""Invalid tool arguments must say what is admitted, not only where the problem is.

Replays the two `start` calls that failed in the 2026-07-27 Codex dogfood. Both were answerable
from the frozen presentation schema, but the response named only field locations, so the agent
read product source and conformance tests to author a request instead.

Nested `/event_drafts/N` failures from the same dogfood must name payload enums (and event
families) rather than falling back to a bare request-template hint.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, cast

import pytest

from yoetz.mcp.descriptors import ORDINARY_MCP_PUBLISH_EVENT_FAMILIES, descriptor_for
from yoetz.mcp.errors import authoring_hint
from yoetz.mcp.resources import read_resource
from yoetz.protocol.canonical import JsonValue

_START_SCHEMA = descriptor_for("start").input_schema
_PUBLISH_SCHEMA = descriptor_for("publish_work").input_schema

_NESTED_ENUM_CASES = (
    ("/event_drafts/0/payload/action_kind", "action_kind", "command"),
    ("/event_drafts/0/payload/outcome", "outcome", "success"),
    ("/event_drafts/0/payload/claim_kind", "claim_kind", "completion"),
    ("/event_drafts/0/payload/evidence_kind", "evidence_kind", "test_result"),
    ("/event_drafts/0/payload/strength", "strength", "content_digest"),
    ("/event_drafts/0/payload/status", "status", "open"),
)


def _locations(*fields: str) -> Sequence[Mapping[str, str]]:
    return tuple({"field": field, "reason": "invalid_value"} for field in fields)


def test_an_unadmitted_mode_is_answered_with_the_admitted_modes() -> None:
    # The dogfood sent `mode: start`, which is not one of the three admitted values.
    hint = authoring_hint(_START_SCHEMA, _locations("/mode"))
    assert "attach, create, create_or_attach" in hint
    assert hint.startswith(" Hint: ")
    assert hint.endswith(".")


def test_a_guessed_request_id_is_answered_with_the_required_shape() -> None:
    # The dogfood sent a free-form id. The shape lives behind a $defs reference.
    hint = authoring_hint(_START_SCHEMA, _locations("/request_id"))
    assert "^req_" in hint


def test_an_empty_request_names_the_constant_versions_and_the_template() -> None:
    hint = authoring_hint(
        _START_SCHEMA, _locations("/protocol_version", "/schema_version", "/mode")
    )
    assert "protocol_version admits 0.1" in hint
    assert "schema_version admits 1.0.0" in hint
    assert "yoetz://guidance/request-templates.md" in hint


def test_the_hint_is_bounded() -> None:
    hint = authoring_hint(
        _START_SCHEMA,
        _locations(
            "/protocol_version", "/schema_version", "/mode", "/request_id", "/requested_view"
        ),
    )
    # At most three fields plus the example pointer, so the hint never buries the locations.
    assert hint.count(" admits ") <= 3


def test_nested_actor_type_names_admitted_values() -> None:
    hint = authoring_hint(_START_SCHEMA, _locations("/actor/actor_type"))
    assert "actor_type admits" in hint
    assert "harness" in hint


def test_unknown_locations_are_skipped() -> None:
    # Unknown names must never be echoed back as admitted labels.
    assert authoring_hint(_START_SCHEMA, _locations("/not_a_field")).count(" admits ") == 0


@pytest.mark.parametrize("schema", [None, "", 7, [], {}, {"properties": "not a mapping"}])
def test_a_malformed_schema_yields_no_hint_rather_than_raising(schema: object) -> None:
    assert authoring_hint(schema, _locations("/mode")) == ""


def test_no_locations_still_points_at_the_template() -> None:
    assert "yoetz://guidance/request-templates.md" in authoring_hint(_START_SCHEMA, ())


def test_a_schema_without_an_example_stays_silent_when_nothing_is_admitted() -> None:
    schema: dict[str, JsonValue] = {"properties": {"mode": {"type": "string"}}}
    assert authoring_hint(schema, _locations("/mode")) == ""


def test_an_oversized_enum_is_not_dumped_into_the_message() -> None:
    schema: dict[str, JsonValue] = {
        # One past the bound: tb4n1 raised it to 16 so status ``view`` (13) and evidence
        # ``digest_binding.subject`` (9) are named.
        "properties": {"mode": {"enum": [f"value_{index}" for index in range(17)]}}
    }
    assert authoring_hint(schema, _locations("/mode")) == ""


def test_an_unbounded_pattern_is_not_dumped_into_the_message() -> None:
    schema: dict[str, JsonValue] = {"properties": {"request_id": {"pattern": "a" * 200}}}
    assert authoring_hint(schema, _locations("/request_id")) == ""


def test_every_workflow_tool_can_produce_a_hint() -> None:
    # A tool whose schema carries no example and no admitted values would leave an agent with the
    # same bare "arguments are invalid" the dogfood got.
    for name in ("start", "publish_work", "check", "respond", "status", "receipt"):
        schema = cast(dict[str, Any], descriptor_for(name).input_schema)
        assert "yoetz://guidance/request-templates.md" in authoring_hint(schema, ()), name


def test_event_draft_index_names_admitted_families_not_bare_fallback() -> None:
    # Run-3 failures #4/#6/#7 landed on /event_drafts/N with only a generic fallback.
    hint = authoring_hint(_PUBLISH_SCHEMA, _locations("/event_drafts/2"))
    # The 2026-08-03 dogfood knew the family values and still guessed the key, so the label names
    # where the discriminator goes rather than calling it an unplaced "event family".
    assert "schema.name admits" in hint
    assert "event family admits" not in hint
    for family in sorted(ORDINARY_MCP_PUBLISH_EVENT_FAMILIES):
        assert family in hint
    assert hint != (" Hint: see yoetz://guidance/request-templates.md for a complete request.")


def test_event_draft_index_names_the_required_envelope_keys() -> None:
    # Naming the admitted families is not enough to author a draft: the agent also needs the
    # seven keys an envelope must carry, and nothing in the rejection said them.
    hint = authoring_hint(_PUBLISH_SCHEMA, _locations("/event_drafts/2"))
    assert "each event_drafts entry requires" in hint
    for key in (
        "event_id",
        "schema",
        "occurred_at",
        "causal_parents",
        "payload",
        "artifact_refs",
        "evidence_refs",
    ):
        assert key in hint


def test_event_draft_payload_union_falls_back_to_the_envelope_hint() -> None:
    # The payload node is a union of family shapes with no enum, const, or pattern of its own,
    # so this pointer reached the caller as a bare template fallback before.
    hint = authoring_hint(_PUBLISH_SCHEMA, _locations("/event_drafts/0/payload"))
    assert "each event_drafts entry requires" in hint
    assert "schema.name admits" in hint


@pytest.mark.parametrize(("pointer", "label", "member"), _NESTED_ENUM_CASES)
def test_nested_payload_enums_name_admitted_members(pointer: str, label: str, member: str) -> None:
    hint = authoring_hint(_PUBLISH_SCHEMA, _locations(pointer))
    assert f"{label} admits" in hint
    assert member in hint
    assert "yoetz://guidance/request-templates.md" in hint


def test_hostile_payload_values_never_appear_in_hints() -> None:
    secret = "never-echo-hostile-payload-value-9f3a"
    # Locations carry only allowlisted pointers; the hint builder must not accept or echo secrets.
    hint = authoring_hint(
        _PUBLISH_SCHEMA,
        (
            {"field": "/event_drafts/0/payload/action_kind", "reason": "invalid_value"},
            {"field": secret, "reason": "invalid_value"},
        ),
    )
    assert secret not in hint
    assert "action_kind admits" in hint


def test_hint_construction_failure_degrades_to_template_fallback() -> None:
    # A hint must never turn a clear validation error into an internal error.
    class _Boom(dict[str, JsonValue]):
        def get(  # type: ignore[override]
            self, key: object, default: object = None
        ) -> object:
            if key == "examples":
                raise RuntimeError("forced_hint_failure")
            return super().get(key, default)  # type: ignore[arg-type]

    schema: Mapping[str, JsonValue] = _Boom(_PUBLISH_SCHEMA)
    hint = authoring_hint(schema, _locations("/event_drafts/0/payload/action_kind"))
    assert hint == (" Hint: see yoetz://guidance/request-templates.md for a complete request.")


def test_envelope_hint_construction_failure_degrades_to_template_fallback() -> None:
    # Same guarantee for the new builders: a forced failure inside them must not raise.
    class _Boom(dict[str, JsonValue]):
        def get(  # type: ignore[override]
            self, key: object, default: object = None
        ) -> object:
            if key == "properties":
                raise RuntimeError("forced_hint_failure")
            return super().get(key, default)  # type: ignore[arg-type]

    schema: Mapping[str, JsonValue] = _Boom(_PUBLISH_SCHEMA)
    assert authoring_hint(schema, _locations("/event_drafts/0")) in {
        "",
        " Hint: see yoetz://guidance/request-templates.md for a complete request.",
    }


def test_the_corrective_registry_stays_closed_over_tools_and_pointers() -> None:
    # A registry that fired on any tool, or on a pointer it was never reviewed for, would be a
    # second uncontrolled prose channel rather than a closed set of checked-in sentences.
    scope_missing = ({"field": "/scope", "reason": "missing"},)
    check_schema = descriptor_for("check").input_schema
    assert "omit scope for the whole case" in authoring_hint(
        check_schema, scope_missing, tool="check"
    )
    # Unregistered tool, unregistered pointer, and unregistered reason each keep it silent.
    assert "omit scope" not in authoring_hint(_START_SCHEMA, scope_missing, tool="start")
    assert "omit scope" not in authoring_hint(
        check_schema, ({"field": "/mode", "reason": "missing"},), tool="check"
    )
    assert "omit scope" not in authoring_hint(
        check_schema, ({"field": "/scope", "reason": "invalid_value"},), tool="check"
    )
    # No tool at all means no registry lookup, and every schema-derived part still arrives.
    assert "omit scope" not in authoring_hint(check_schema, scope_missing)
    assert "scope requires claim_ids and obligation_ids" in authoring_hint(
        check_schema, ({"field": "/scope/claim_ids", "reason": "missing"},)
    )


def test_a_required_peer_hint_never_names_an_unallowlisted_parent() -> None:
    secret = "hostile_parent_key"
    hint = authoring_hint(
        _START_SCHEMA, ({"field": f"/{secret}/leaf", "reason": "missing"},), tool="start"
    )
    assert secret not in hint


def test_no_caller_value_reaches_the_new_hint_parts() -> None:
    secret = "never-echo-this-corrective-value-4c1d"
    hint = authoring_hint(
        descriptor_for("check").input_schema,
        (
            {"field": "/scope/claim_ids", "reason": "missing"},
            {"field": secret, "reason": "missing"},
            {"field": f"/scope/{secret}", "reason": "missing"},
        ),
        tool="check",
    )
    assert secret not in hint
    assert "scope requires claim_ids and obligation_ids" in hint


def test_every_required_schema_name_can_be_located_in_a_public_error() -> None:
    """A required name outside the allowlist reports its parent as missing when it was sent."""

    from yoetz.mcp.errors import (
        _DELIBERATELY_UNLOCATABLE,  # pyright: ignore[reportPrivateUsage]
        _SAFE_LOCATION_SEGMENTS,  # pyright: ignore[reportPrivateUsage]
    )

    def walk(node: object, found: set[str]) -> None:
        if isinstance(node, Mapping):
            source = cast(Mapping[str, Any], node)
            required = source.get("required")
            if isinstance(required, list):
                found.update(item for item in cast(list[object], required) if type(item) is str)
            for value in source.values():
                walk(value, found)
        elif isinstance(node, list):
            for value in cast(list[object], node):
                walk(value, found)

    found: set[str] = set()
    for name in ("start", "publish_work", "check", "respond", "status", "receipt"):
        walk(descriptor_for(name).input_schema, found)
    assert found
    assert not found - _SAFE_LOCATION_SEGMENTS - _DELIBERATELY_UNLOCATABLE
    # The escape hatch stays a reviewed decision rather than a growing exemption list.
    assert _DELIBERATELY_UNLOCATABLE == frozenset()


def test_publish_work_examples_cover_ordinary_families_and_cross_refs() -> None:
    examples = cast(list[JsonValue], _PUBLISH_SCHEMA["examples"])
    families: set[str] = set()
    for example in examples:
        assert isinstance(example, Mapping)
        drafts = cast(Mapping[str, JsonValue], example).get("event_drafts")
        assert isinstance(drafts, list)
        for draft in cast(list[JsonValue], drafts):
            assert isinstance(draft, Mapping)
            schema = cast(Mapping[str, JsonValue], draft).get("schema")
            assert isinstance(schema, Mapping)
            name = cast(Mapping[str, JsonValue], schema).get("name")
            assert type(name) is str
            families.add(name)
    assert ORDINARY_MCP_PUBLISH_EVENT_FAMILIES <= families
    # Cross-event refs: claim supporting_refs point at an evidence id from the same batch.
    cross = cast(Mapping[str, JsonValue], examples[2])
    drafts = cast(list[JsonValue], cross["event_drafts"])
    evidence_ids: set[str] = set()
    for d in drafts:
        draft_map = cast(Mapping[str, JsonValue], d)
        schema_map = cast(Mapping[str, JsonValue], draft_map["schema"])
        if schema_map["name"] != "evidence_recorded":
            continue
        payload_map = cast(Mapping[str, JsonValue], draft_map["payload"])
        evidence_value = payload_map["evidence_id"]
        assert type(evidence_value) is str
        evidence_ids.add(evidence_value)
    claim = next(
        cast(Mapping[str, JsonValue], cast(Mapping[str, JsonValue], d)["payload"])
        for d in drafts
        if cast(Mapping[str, JsonValue], cast(Mapping[str, JsonValue], d)["schema"])["name"]
        == "claim_recorded"
    )
    supporting = cast(list[JsonValue], claim["supporting_refs"])
    assert evidence_ids
    assert set(supporting) & evidence_ids


def test_publish_work_examples_include_obligation_resolution_pair() -> None:
    """Agents must see an open obligation and its byte-identical resolution side by side."""

    examples = cast(list[JsonValue], _PUBLISH_SCHEMA["examples"])
    resolution_example = next(
        cast(Mapping[str, JsonValue], example)
        for example in examples
        if any(
            cast(Mapping[str, JsonValue], cast(Mapping[str, JsonValue], draft)["schema"])["name"]
            == "obligation_published"
            and cast(Mapping[str, JsonValue], cast(Mapping[str, JsonValue], draft)["payload"]).get(
                "status"
            )
            == "resolved"
            for draft in cast(
                list[JsonValue], cast(Mapping[str, JsonValue], example)["event_drafts"]
            )
        )
    )
    drafts = cast(list[JsonValue], resolution_example["event_drafts"])
    open_payload: Mapping[str, JsonValue] | None = None
    resolved_payload: Mapping[str, JsonValue] | None = None
    evidence_ids: set[str] = set()
    for draft in drafts:
        draft_map = cast(Mapping[str, JsonValue], draft)
        schema_map = cast(Mapping[str, JsonValue], draft_map["schema"])
        payload_map = cast(Mapping[str, JsonValue], draft_map["payload"])
        if schema_map["name"] == "evidence_recorded":
            evidence_value = payload_map["evidence_id"]
            assert type(evidence_value) is str
            evidence_ids.add(evidence_value)
        if schema_map["name"] != "obligation_published":
            continue
        if payload_map.get("status") == "open":
            open_payload = payload_map
        elif payload_map.get("status") == "resolved":
            resolved_payload = payload_map
    assert open_payload is not None
    assert resolved_payload is not None
    for field in (
        "obligation_id",
        "description",
        "acceptance_criteria",
        "evidence_expectation",
        "requested_items",
    ):
        assert open_payload[field] == resolved_payload[field]
    refs = cast(list[JsonValue], resolved_payload["resolution_evidence_refs"])
    assert evidence_ids
    assert set(refs) <= evidence_ids


def test_request_templates_document_requested_item_kinds() -> None:
    """Issue #318: the obligation template must name admitted kinds before the first publish."""

    text = read_resource("yoetz://guidance/request-templates.md").decode("utf-8")
    assert "`item_kind` admits `change`, `command`, `file`, `source`, `url`" in text, (
        "the authoring fallback never listed the closed item_kind enum"
    )
    assert "`outcome` is not an admitted `item_kind`" in text
    assert "requested outcome in `description` and\n`acceptance_criteria`" in text
    assert "acceptance evidence in `evidence_expectation`" in text
    assert '"item_kind": "change"' in text
    assert '"item_kind": "command"' in text
    assert '"item_kind": "outcome"' not in text


def test_publication_policy_documents_obligation_resolution_rule() -> None:
    text = read_resource("yoetz://guidance/publication-policy.md").decode("utf-8")
    assert "obligation-resolution" in text or "Obligation resolution" in text
    assert "meaning_fields_must_repeat" in text or "byte-for-byte" in text
    assert "resolution_evidence_refs" in text


def test_every_worked_example_validates_against_its_request_schema() -> None:
    from yoetz.protocol.models import (
        CheckRequestModel,
        PublishWorkRequestModel,
        ReceiptRequestModel,
        RespondRequestModel,
        StartRequestModel,
        StatusRequestModel,
    )

    validators = {
        "start": StartRequestModel,
        "publish_work": PublishWorkRequestModel,
        "check": CheckRequestModel,
        "respond": RespondRequestModel,
        "status": StatusRequestModel,
        "receipt": ReceiptRequestModel,
    }
    for name, model in validators.items():
        schema = descriptor_for(name).input_schema
        examples = cast(list[JsonValue], schema["examples"])
        for example in examples:
            model.model_validate(example)


def test_guidance_uris_in_tool_descriptions_resolve() -> None:
    for name in ("start", "publish_work", "check", "respond", "status", "receipt"):
        description = descriptor_for(name).description
        assert "yoetz://guidance/" in description
        for resource in description.split("yoetz://guidance/")[1:]:
            name = resource.split(".md", 1)[0] + ".md"
            payload = read_resource("yoetz://guidance/" + name)
            assert payload.startswith(b"#") or payload.startswith(b"Yoetz")


def test_invalid_request_message_names_registered_guidance() -> None:
    from yoetz.mcp.server import invalid_request_message

    publish_message = invalid_request_message(
        "publish_work", _locations("/event_drafts/0/payload/action_kind")
    )
    assert "action_kind admits" in publish_message
    assert "yoetz://guidance/request-templates.md" in publish_message
    start_message = invalid_request_message("start", _locations("/mode"))
    assert "yoetz://guidance/request-templates.md" in start_message
