"""A misplaced known field must be answered with its one legal owning family.

Replays the 2026-08-14 dogfood: `attempted_items` published on `claim_recorded.payload` was
rejected with the claim family's admitted keys (issue #240 working as designed), but nothing said
the field is legal on `action_recorded.payload`, so the agent repaired by deleting it and the
accepted batch silently lost requested-item attempt accounting (issue #266).

The request stays rejected. The addition is one bounded repair fact — in `safe_details`, in the
authoring hint, and in the compatible text summary — whose every value is frozen schema or
registry content. Ambiguous fields, envelope-owned fields, and caller-invented keys never receive
ownership guidance.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, cast

import pytest
from pydantic import ValidationError

import finishup.mcp.server as bridge
from builders.publish_identity import bridge_bound
from finishup.mcp.descriptors import ORDINARY_MCP_PUBLISH_EVENT_FAMILIES, descriptor_for
from finishup.mcp.errors import safe_validation_locations
from finishup.mcp.server import invalid_request_message
from finishup.mcp.summaries import MAX_SUMMARY_BYTES, render_safe_compact_summary
from finishup.protocol.errors import PublicErrorCode
from finishup.protocol.models import PublishWorkRequestModel

_PUBLISH_SCHEMA = descriptor_for("publish_work").input_schema
_TEMPLATE_URI = "finishup://guidance/request-templates.md"
_REPAIR_KEYS = (
    "repair_field",
    "repair_kind",
    "repair_owning_family",
    "repair_selected_family",
    "repair_template_uri",
)
# The public message bound the protocol validator enforces.
_MAX_MESSAGE_BYTES = 4096


def _single_draft_request(family: str) -> dict[str, Any]:
    """One worked example reduced to its single draft of ``family``."""

    examples = cast(list[Any], _PUBLISH_SCHEMA["examples"])
    for example in examples:
        for draft in cast(list[Any], example["event_drafts"]):
            if draft["schema"]["name"] != family:
                continue
            request = cast(dict[str, Any], json.loads(json.dumps(example)))
            request["event_drafts"] = [json.loads(json.dumps(draft))]
            return request
    raise AssertionError(f"the publish_work examples no longer carry a {family} draft")


def _with_payload_keys(family: str, **extra: Any) -> dict[str, Any]:
    request = _single_draft_request(family)
    payload = cast(dict[str, Any], request["event_drafts"][0]["payload"])
    for key in tuple(extra):
        # An example that already carries the key would not produce extra_forbidden.
        payload.pop(key, None)
    payload.update(extra)
    return request


def _locations(request: Mapping[str, Any]) -> tuple[dict[str, str], ...]:
    with pytest.raises(ValidationError) as captured:
        PublishWorkRequestModel.model_validate(bridge_bound(request))
    return safe_validation_locations(captured.value)


def _misplaced_attempted_items_request() -> dict[str, Any]:
    return _with_payload_keys("claim_recorded", attempted_items=["pytest -q"])


async def _dry_run_result(
    monkeypatch: pytest.MonkeyPatch, request: dict[str, Any]
) -> tuple[object, dict[str, object]]:
    async def refuse(_runtime: object = bridge.BRIDGE_RUNTIME) -> object:
        raise AssertionError("a dry run must not reach the recovery oracle")

    monkeypatch.setattr(bridge, "ensure_service_client", refuse)
    runtime = bridge.build_bridge_runtime()
    result = await bridge.dispatch_publish_work({**request, "dry_run": True}, runtime)
    await bridge.close_bridge_runtime(runtime)
    structured = cast(dict[str, object], result.structuredContent)
    return result, structured


def test_misplaced_attempted_items_stays_rejected_with_extra_forbidden() -> None:
    locations = _locations(_misplaced_attempted_items_request())

    assert locations[0]["field"] == "/event_drafts/0/payload"
    assert locations[0]["reason"] == "extra_forbidden"
    assert locations[0]["family"] == "claim_recorded"
    assert locations[0]["misplaced_field"] == "attempted_items"


def test_the_hint_names_the_sole_owning_family_beside_the_admitted_keys() -> None:
    locations = _locations(_misplaced_attempted_items_request())
    message = invalid_request_message("publish_work", locations)

    assert len(message.encode("utf-8")) <= _MAX_MESSAGE_BYTES
    # Issue #240's admitted-key recital is preserved untouched...
    assert "the claim_recorded schema does not admit" in message
    assert "supporting_refs" in message
    # ...and the one new bounded ownership sentence sits beside it.
    assert "attempted_items is admitted only by the action_recorded payload" in message
    assert _TEMPLATE_URI in message


@pytest.mark.anyio
async def test_the_repair_fact_reaches_safe_details_in_structured_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, structured = await _dry_run_result(monkeypatch, _misplaced_attempted_items_request())

    error = cast(dict[str, object], structured["error"])
    assert error["code"] == PublicErrorCode.INVALID_REQUEST.value
    details = cast(dict[str, object], error["safe_details"])
    assert set(details) == {"continuation", "fields", "reasons", *_REPAIR_KEYS}
    assert details["reasons"] == ["extra_forbidden"]
    # The repair fact's directive rides as the typed continuation (ADR-030): this producer is the
    # only one that emits the ownership repair, and previously nothing attached its token.
    assert details["continuation"] == "field_ownership_repair"
    assert details["repair_kind"] == "field_ownership"
    assert details["repair_field"] == "attempted_items"
    assert details["repair_selected_family"] == "claim_recorded"
    assert details["repair_owning_family"] == "action_recorded"
    assert details["repair_template_uri"] == _TEMPLATE_URI
    # ASCII key order is the documented wire order for safe_details.
    assert list(details) == sorted(details)


@pytest.mark.anyio
async def test_the_repair_fact_reaches_the_compatible_text_channel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, structured = await _dry_run_result(monkeypatch, _misplaced_attempted_items_request())

    summary = render_safe_compact_summary(structured)
    assert "Repair: attempted_items is admitted only by the action_recorded payload" in summary
    assert "Continuation: field_ownership_repair." in summary
    assert len(summary.encode("ascii")) <= MAX_SUMMARY_BYTES
    content = cast(list[Any], getattr(result, "content"))
    assert content[0].text == summary


def test_a_caller_invented_key_receives_no_ownership_guidance() -> None:
    locations = _locations(_with_payload_keys("claim_recorded", zzz_unknown="x"))

    assert locations[0]["reason"] == "extra_forbidden"
    assert "misplaced_field" not in locations[0]
    message = invalid_request_message("publish_work", locations)
    assert "admitted only by" not in message


@pytest.mark.anyio
async def test_an_ambiguous_field_keeps_the_current_admitted_key_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`statement` is declared by claim_recorded and decision_recorded: no invented owner."""

    request = _with_payload_keys("action_recorded", statement="misplaced")
    locations = _locations(request)
    assert locations[0]["reason"] == "extra_forbidden"
    assert locations[0]["misplaced_field"] == "statement"

    message = invalid_request_message("publish_work", locations)
    assert "admitted only by" not in message

    _, structured = await _dry_run_result(monkeypatch, request)
    error = cast(dict[str, object], structured["error"])
    details = cast(dict[str, object], error["safe_details"])
    assert set(details) == {"continuation", "fields", "reasons"}
    assert details["continuation"] == "input_correction_new_identity"


def test_an_envelope_owned_key_is_not_called_misplaced_across_families() -> None:
    """`evidence_refs` inside a payload is misplaced across levels, not families."""

    locations = _locations(
        _with_payload_keys(
            "claim_recorded", evidence_refs=["evd_00000000-0000-4000-8000-000000000001"]
        )
    )

    assert locations[0]["reason"] == "extra_forbidden"
    assert "misplaced_field" not in locations[0]
    message = invalid_request_message("publish_work", locations)
    assert "admitted only by" not in message


def test_a_key_owned_by_another_version_of_the_same_family_gets_no_repair() -> None:
    """`digest_binding` on evidence_recorded 1.0.0 is a version defect, not a family defect."""

    request = _single_draft_request("evidence_recorded")
    draft = cast(dict[str, Any], request["event_drafts"][0])
    if draft["schema"]["version"] != "1.0.0":
        draft["schema"]["version"] = "1.0.0"
        cast(dict[str, Any], draft["payload"]).pop("digest_binding", None)
    cast(dict[str, Any], draft["payload"])["digest_binding"] = {
        "subject": "test_stdout",
        "content_availability": "digest_only",
        "byte_count": 1,
        "provenance": "caller_asserted",
    }

    locations = _locations(request)
    assert locations[0]["reason"] == "extra_forbidden"
    message = invalid_request_message("publish_work", locations)
    assert "admitted only by" not in message


def test_several_misplaced_fields_pick_the_ascii_first_deterministically() -> None:
    locations = _locations(
        _with_payload_keys(
            "claim_recorded", attempted_items=["pytest -q"], authority="harness:test"
        )
    )

    assert locations[0]["count"] == "2"
    assert locations[0]["misplaced_field"] == "attempted_items"


@pytest.mark.anyio
async def test_hostile_sibling_keys_never_reach_the_repair_surfaces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "never_echo_hostile_key_9d4e"
    request = _with_payload_keys(
        "claim_recorded", **{"attempted_items": ["pytest -q"], secret: "x"}
    )

    locations = _locations(request)
    assert locations[0]["misplaced_field"] == "attempted_items"
    message = invalid_request_message("publish_work", locations)
    assert secret not in message

    _, structured = await _dry_run_result(monkeypatch, request)
    assert secret not in str(structured)
    assert secret not in render_safe_compact_summary(structured)


def test_one_retry_moves_the_field_instead_of_deleting_it() -> None:
    """The repair fact alone is enough to relocate the record without losing it."""

    request = _misplaced_attempted_items_request()
    locations = _locations(request)
    misplaced = locations[0]["misplaced_field"]

    from finishup.mcp.errors import _FIELD_OWNERSHIP  # pyright: ignore[reportPrivateUsage]

    owner = _FIELD_OWNERSHIP[misplaced]
    assert owner == "action_recorded"

    claim_draft = cast(dict[str, Any], request["event_drafts"][0])
    moved_value = cast(dict[str, Any], claim_draft["payload"]).pop(misplaced)
    owner_request = _single_draft_request(owner)
    owner_draft = cast(dict[str, Any], owner_request["event_drafts"][0])
    cast(dict[str, Any], owner_draft["payload"])[misplaced] = moved_value
    owner_draft["event_id"] = "evt_00000000-0000-4000-8000-000000000099"
    request["event_drafts"] = [owner_draft, claim_draft]

    repaired = PublishWorkRequestModel.model_validate(bridge_bound(request))
    payloads = cast(tuple[Any, ...], repaired.event_drafts)
    assert cast(dict[str, Any], payloads[0])["payload"][misplaced] == ["pytest -q"]


def test_the_ownership_registry_stays_closed_and_pinned() -> None:
    from finishup.mcp.errors import (
        _FIELD_OWNERSHIP,  # pyright: ignore[reportPrivateUsage]
        _SAFE_LOCATION_SEGMENTS,  # pyright: ignore[reportPrivateUsage]
    )

    assert _FIELD_OWNERSHIP["attempted_items"] == "action_recorded"
    assert _FIELD_OWNERSHIP["requested_items"] == "obligation_published"
    assert _FIELD_OWNERSHIP["authority"] == "decision_recorded"
    # Ambiguous fields must stay out: guessing an owner is worse than the admitted-key answer.
    for ambiguous in ("statement", "summary", "description", "subject_state", "obligation_refs"):
        assert ambiguous not in _FIELD_OWNERSHIP, ambiguous
    for field, family in _FIELD_OWNERSHIP.items():
        assert field in _SAFE_LOCATION_SEGMENTS
        assert family in ORDINARY_MCP_PUBLISH_EVENT_FAMILIES
    assert list(_FIELD_OWNERSHIP) == sorted(_FIELD_OWNERSHIP)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
