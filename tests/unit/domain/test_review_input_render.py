"""Shared public projections for the bounded review-input manifest."""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Mapping

from finishup.domain.events import PAYLOAD_TYPES, EventSchema
from finishup.domain.review_input_render import (
    _PUBLISH_EXACTLY,  # pyright: ignore[reportPrivateUsage]
    FINISHUP_LIMIT_MISSING_TEXT,
    MISSING_SUPPLY_SENTENCE,
    has_agent_suppliable_missing,
    render_missing_for_assessment_lines,
    render_missing_for_assessment_next,
    render_review_input_manifest_compact,
    render_review_input_manifest_compat_line,
    render_review_input_manifest_coverage_note,
    render_review_input_manifest_lines,
)
from finishup.protocol.schemas import SchemaArtifactRole, load_schema_catalog

_DIGEST = "sha256:" + "a" * 64


def _section(status: str, *, digest: str | None = _DIGEST) -> dict[str, object]:
    return {
        "status": status,
        "source_refs": ["evt_00000000-0000-4000-8000-000000000001"],
        "item_ids": ["item-1"],
        "omitted_refs": [],
        "omission_reasons": [],
        "revision": 7,
        "content_digest": digest,
        "content_bytes": 123,
    }


def _manifest(*, specification_status: str = "complete") -> dict[str, object]:
    return {
        "schema": "yoetz.review-input-manifest/1",
        "specification": _section(specification_status),
        "current_diff": _section("partial"),
        "caller_evidence": _section("missing", digest=None),
        "latest_verification": _section("complete"),
        "prior_finding_context": _section("not_selected", digest=None),
        "phase": "provider_bound",
        "missing_inputs": [
            {
                "kind": "verification_output",
                "status": "pending",
                "target_refs": ["res_00000000-0000-4000-8000-000000000002"],
                "supplied_refs": [],
            }
        ],
        "selected_item_count": 3,
        "selected_excerpt_bytes": 246,
        "omitted_item_count": 2,
    }


def test_manifest_renderer_keeps_distinct_statement_state_and_digests() -> None:
    lines = render_review_input_manifest_lines(_manifest(specification_status="title_only"))

    assert lines[0] == (
        "Review input manifest: provider_bound; selected items 3; "
        "selected excerpt bytes 246; omitted items 2."
    )
    assert any(line.startswith("- specification: title_only;") for line in lines)
    assert any(_DIGEST in line for line in lines)
    assert any("Manifest missing inputs: verification_output=pending" in line for line in lines)
    assert "Provider-bound review input: specification complete" in (
        render_review_input_manifest_compat_line(_manifest())
    )
    assert "provider_bound" in render_review_input_manifest_compact(_manifest())


def test_manifest_renderer_reports_the_true_omission_total_beside_the_listed_cap() -> None:
    # Issue #976 (tb4n1 D11): the listed count saturates at 64; the total does not.
    manifest = _manifest()
    manifest["omitted_item_count"] = 64
    manifest["omitted_item_total"] = 173

    lines = render_review_input_manifest_lines(manifest)

    assert lines[0].endswith("; omitted items 173 (64 listed).")
    assert "omitted items 173 (64 listed)" in render_review_input_manifest_compact(manifest)
    manifest["omitted_item_total"] = 64
    assert render_review_input_manifest_lines(manifest)[0].endswith("; omitted items 64.")
    # An older manifest without the total keeps its listed count; a malformed total is ignored.
    manifest["omitted_item_total"] = "many"
    assert render_review_input_manifest_lines(manifest)[0].endswith("; omitted items 64.")


def test_manifest_renderer_rejects_untrusted_or_incomplete_shapes() -> None:
    assert render_review_input_manifest_lines({"schema": "other"}) == ()
    malformed = _manifest()
    malformed["selected_item_count"] = "3"
    assert render_review_input_manifest_lines(malformed) == ()


def test_receipt_note_lists_missing_availability_without_content() -> None:
    note = render_review_input_manifest_coverage_note(
        _manifest(),
        [
            {
                "kind": "task_statement",
                "target_refs": ["clm_00000000-0000-4000-8000-000000000003"],
                "availability": "agent_suppliable",
            }
        ],
    )

    assert note is not None
    assert "Review input coverage (metadata only):" in note
    assert "specification: complete" in note
    assert "task_statement (1 target refs): agent_suppliable" in note
    assert len(note.encode("utf-8")) <= 4096


def test_missing_renderer_preserves_refs_for_cli_and_mcp_surfaces() -> None:
    lines = render_missing_for_assessment_lines(
        [
            {
                "kind": "current_diff_for_path",
                "target_refs": ["evd_00000000-0000-4000-8000-000000000004"],
                "availability": "structurally_unavailable_on_this_host",
            }
        ]
    )

    assert lines == (
        "Missing for assessment (the reviewer could not assess the packet):",
        "- current_diff_for_path (evd_00000000-0000-4000-8000-000000000004): "
        "structurally_unavailable_on_this_host",
    )


def test_missing_renderer_prioritizes_agent_suppliable_input_over_a_receipt() -> None:
    items = [
        {
            "kind": "verification_output",
            "target_refs": ["res_00000000-0000-4000-8000-000000000002"],
            "availability": "agent_suppliable",
        }
    ]

    assert has_agent_suppliable_missing(items)
    assert render_missing_for_assessment_next(items) == "Overall next: " + MISSING_SUPPLY_SENTENCE
    lines = render_missing_for_assessment_lines(items)
    assert lines[-1] == render_missing_for_assessment_next(items)
    assert "result_recorded of that target whose summary is the command output" in lines[1]


def test_finishup_limit_items_are_named_as_finishup_limits_never_agent_work() -> None:
    """tb4n1 D1/F2 (#983): an unshowable item tells the agent to self-verify, never to reshape."""

    items = [
        {
            "kind": "other",
            "target_refs": ["evd_00000000-0000-4000-8000-000000000002"],
            "availability": "yoetz_limit_unsupported_data_type",
        }
    ]
    assert not has_agent_suppliable_missing(items)
    assert render_missing_for_assessment_next(items) == ""
    lines = render_missing_for_assessment_lines(items)
    assert (
        "- other (evd_00000000-0000-4000-8000-000000000002): yoetz_limit_unsupported_data_type"
        in lines
    )
    assert lines[-1] == FINISHUP_LIMIT_MISSING_TEXT
    assert "never a blocker" in FINISHUP_LIMIT_MISSING_TEXT
    assert "git-add" in FINISHUP_LIMIT_MISSING_TEXT


# Prose subjects the publish instructions use for an event family.
_EVENT_SUBJECTS = {"action": "action_recorded", "evidence": "evidence_recorded"}


def _event_versions(name: str) -> tuple[str, ...]:
    return tuple(sorted(schema.version for schema in PAYLOAD_TYPES if schema.name == name))


def _schema_fields(name: str, version: str) -> frozenset[str]:
    wanted = name.replace("_", "-")
    matched = [
        document
        for document in load_schema_catalog().documents
        if document.artifact_role is SchemaArtifactRole.EVENT_PAYLOAD
        and document.schema_name == wanted
        and document.schema_version == version
    ]
    assert len(matched) == 1, (name, version)
    properties = matched[0].json_schema["properties"]
    assert isinstance(properties, Mapping)
    return frozenset(str(key) for key in properties)


def _model_fields(name: str, version: str) -> frozenset[str]:
    payload = PAYLOAD_TYPES[EventSchema(name, version)]
    return frozenset(item.name for item in dataclasses.fields(payload))


def _publish_claims(instruction: str) -> list[tuple[str, str | None, str | None]]:
    """Event mentions and the payload fields each instruction attributes to them."""

    families = frozenset(schema.name for schema in PAYLOAD_TYPES)
    events: list[tuple[int, int, str, str | None]] = []
    for match in re.finditer(r"\b([a-z][a-z0-9_]*)\b(?:\s+(\d+\.\d+\.\d+))?", instruction):
        name, version = match.group(1), match.group(2)
        if name in families:
            events.append((match.start(), match.end(), name, version))
    claims: list[tuple[str, str | None, str | None]] = [
        (name, version, None) for _start, _end, name, version in events
    ]

    def event_before(offset: int) -> tuple[str, str | None] | None:
        earlier = [item for item in events if item[1] <= offset]
        if not earlier:
            return None
        return earlier[-1][2], earlier[-1][3]

    claimed_fields: set[str] = set()
    for match in re.finditer(r"\bwhose\s+([a-z][a-z0-9_]*)", instruction):
        named = event_before(match.start())
        if named is None:
            subject = re.search(r"\b([a-z_]+)\s+$", instruction[: match.start()])
            assert subject is not None, instruction
            alias = _EVENT_SUBJECTS.get(subject.group(1))
            assert alias is not None, (subject.group(1), instruction)
            named = (alias, None)
        claims.append((named[0], named[1], match.group(1)))
        claimed_fields.add(match.group(1))
    for match in re.finditer(r"\bwith its\s+([a-z][a-z0-9_]*)", instruction):
        named = event_before(match.start())
        assert named is not None, instruction
        claims.append((named[0], named[1], match.group(1)))
        claimed_fields.add(match.group(1))
    for match in re.finditer(r"\b([a-z]+)'s(?:\s+exact)?\s+([a-z][a-z0-9_]*)", instruction):
        subject = match.group(1)
        event = _EVENT_SUBJECTS.get(subject)
        if event is None and subject not in families:
            continue
        claims.append((event or subject, None, match.group(2)))
        claimed_fields.add(match.group(2))
    for token in re.findall(r"\b[a-z]+_[a-z0-9_]+\b", instruction):
        assert token in families or token in claimed_fields, (token, instruction)
    return claims


def test_publish_exactly_names_fields_the_payload_admits() -> None:
    """Each named event exists, and each named field exists on that version's payload."""

    assert _PUBLISH_EXACTLY["task_statement"] == (
        "Publish one plan_revised 1.1.0 whose task_statement is the user's whole request, "
        "linked to the target."
    )
    checked = 0
    for instruction in _PUBLISH_EXACTLY.values():
        for event, version, field in _publish_claims(instruction):
            versions = (version,) if version is not None else _event_versions(event)
            assert versions, event
            for item in versions:
                assert EventSchema(event, item) in PAYLOAD_TYPES
                if field is None:
                    continue
                assert field in _schema_fields(event, item), (event, item, field)
                assert field in _model_fields(event, item), (event, item, field)
                checked += 1
    assert checked >= 1


def test_recorded_manifest_accepts_the_omission_total_and_refuses_a_smaller_one() -> None:
    import pytest

    from finishup.domain.events import (
        _review_input_manifest_from_json,  # pyright: ignore[reportPrivateUsage]
    )
    from finishup.protocol.errors import ProtocolValueError

    manifest = _manifest()
    manifest["omitted_item_count"] = 64
    manifest["omitted_item_total"] = 173
    frozen = _review_input_manifest_from_json(manifest)  # pyright: ignore[reportArgumentType]
    assert frozen is not None and frozen["omitted_item_total"] == 173
    del manifest["omitted_item_total"]
    assert _review_input_manifest_from_json(manifest) is not None  # pyright: ignore[reportArgumentType]
    for invalid in (63, "173", None):
        manifest["omitted_item_total"] = invalid
        with pytest.raises(ProtocolValueError):
            _review_input_manifest_from_json(manifest)  # pyright: ignore[reportArgumentType]
