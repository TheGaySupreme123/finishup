"""An unknown payload key must be named as such, never answered with satisfied requirements.

Replays the 2026-08-13 dogfood: `publish_work` drafts whose `obligation_published` payloads were
rejected for keys the family does not admit. The response recited the seven envelope keys the
request already carried and the family value it had already sent, and never said "unknown
property" (issue #240). The rejected key names stay caller-controlled and must never be echoed;
the admitted keys and a bounded count are frozen schema facts and must be.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, cast

import pytest
from pydantic import ValidationError

import finishup.mcp.server as bridge
from builders.publish_identity import bridge_bound
from finishup.mcp.descriptors import descriptor_for
from finishup.mcp.errors import authoring_hint, safe_validation_locations
from finishup.mcp.server import invalid_request_message
from finishup.protocol.errors import PublicErrorCode
from finishup.protocol.models import PublishWorkRequestModel

_PUBLISH_SCHEMA = descriptor_for("publish_work").input_schema
_FAMILY = "obligation_published"
_ADMITTED_PAYLOAD_KEYS = (
    "acceptance_criteria",
    "description",
    "evidence_expectation",
    "obligation_id",
    "requested_items",
    "resolution_evidence_refs",
    "source_refs",
    "status",
)
# The one family the catalogue and presentation schema admit at two versions, and the payload key
# only the later one admits.
_MULTI_VERSION_FAMILY = "evidence_recorded"
_LATER_ONLY_PAYLOAD_KEY = "digest_binding"
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


def _obligation_request() -> dict[str, Any]:
    return _single_draft_request(_FAMILY)


def _locations(request: Mapping[str, Any]) -> tuple[dict[str, str], ...]:
    with pytest.raises(ValidationError) as captured:
        PublishWorkRequestModel.model_validate(bridge_bound(request))
    return safe_validation_locations(captured.value)


def _message(request: Mapping[str, Any]) -> str:
    message = invalid_request_message("publish_work", _locations(request))
    assert len(message.encode("utf-8")) <= _MAX_MESSAGE_BYTES
    return message


def _with_payload_keys(**extra: Any) -> dict[str, Any]:
    request = _obligation_request()
    request["event_drafts"][0]["payload"].update(extra)
    return request


def test_unknown_payload_key_reports_extra_forbidden() -> None:
    locations = _locations(_with_payload_keys(zzz_unknown="x"))

    assert locations[0]["field"] == "/event_drafts/0/payload"
    assert locations[0]["reason"] == "extra_forbidden"


def test_unknown_payload_key_names_the_admitted_keys_for_the_family() -> None:
    message = _message(_with_payload_keys(zzz_unknown="x"))

    assert "does not admit" in message
    assert _FAMILY in message
    for key in _ADMITTED_PAYLOAD_KEYS:
        assert key in message, key


def test_a_single_version_family_is_answered_with_its_own_version_and_full_key_list() -> None:
    """The ordinary case: one admitted version, so the named-key hint is exactly right."""

    locations = _locations(_with_payload_keys(zzz_unknown="x"))

    assert locations[0]["family"] == _FAMILY
    assert locations[0]["family_version"] == "1.0.0"
    message = invalid_request_message("publish_work", locations)
    assert f"the {_FAMILY} schema does not admit" in message
    for key in _ADMITTED_PAYLOAD_KEYS:
        assert key in message, key


def test_a_later_family_version_is_answered_with_its_own_key_list() -> None:
    """A 1.1.0 evidence payload receives the matching advertised contract (issues #239, #246)."""

    request = _single_draft_request(_MULTI_VERSION_FAMILY)
    example_version = cast(str, request["event_drafts"][0]["schema"]["version"])
    assert example_version != "1.0.0", "pick a later-version worked example"
    assert _LATER_ONLY_PAYLOAD_KEY in request["event_drafts"][0]["payload"]
    request["event_drafts"][0]["payload"]["zzz_unknown"] = "x"

    locations = _locations(request)
    message = invalid_request_message("publish_work", locations)

    assert locations[0]["family"] == _MULTI_VERSION_FAMILY
    assert locations[0]["family_version"] == example_version
    assert f"the {_MULTI_VERSION_FAMILY} schema does not admit" in message
    assert "admitted keys are" in message
    assert _LATER_ONLY_PAYLOAD_KEY in message
    assert len(message.encode("utf-8")) <= _MAX_MESSAGE_BYTES


def test_unknown_payload_count_reports_saturation_as_a_lower_bound() -> None:
    request = _obligation_request()
    request["event_drafts"][0]["payload"].update({f"unknown_{index}": "x" for index in range(33)})

    message = _message(request)

    assert "at least 32 properties" in message
    assert "carries 32 properties" not in message


def test_a_family_without_a_version_gets_no_key_list() -> None:
    """Nothing pairs a key list with a family until the version beside it is known."""

    named = authoring_hint(
        _PUBLISH_SCHEMA,
        (
            {
                "field": "/event_drafts/0/payload",
                "reason": "extra_forbidden",
                "family": _FAMILY,
                "family_version": "1.0.0",
                "count": "1",
            },
        ),
    )
    assert "admitted keys are" in named
    for location in (
        {"field": "/event_drafts/0/payload", "reason": "extra_forbidden", "family": _FAMILY},
        {
            "field": "/event_drafts/0/payload",
            "reason": "extra_forbidden",
            "family": _FAMILY,
            "family_version": "9.9.9",
        },
    ):
        degraded = authoring_hint(_PUBLISH_SCHEMA, (location,))
        assert "admitted keys are" not in degraded
        assert "the event schema does not admit" in degraded
        assert "schema.name admits" in degraded


def test_unknown_payload_key_does_not_recite_satisfied_envelope_requirements() -> None:
    message = _message(_with_payload_keys(zzz_unknown="x"))

    assert "each event_drafts entry requires" not in message


@pytest.mark.anyio
async def test_unknown_payload_key_never_echoes_the_key_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "never_echo_unknown_key_7b2c"
    request = _with_payload_keys(**{secret: "x"})

    locations = _locations(request)
    message = invalid_request_message("publish_work", locations)
    assert secret not in message
    assert secret not in repr(locations)

    async def refuse(_runtime: object = bridge.BRIDGE_RUNTIME) -> object:
        raise AssertionError("a dry run must not reach the recovery oracle")

    monkeypatch.setattr(bridge, "ensure_service_client", refuse)
    runtime = bridge.build_bridge_runtime()
    result = await bridge.dispatch_publish_work({**request, "dry_run": True}, runtime)
    assert secret not in str(result.structuredContent)
    await bridge.close_bridge_runtime(runtime)


def test_unknown_payload_key_count_reaches_the_caller() -> None:
    request = _with_payload_keys(zzz_unknown="x", aaa_unknown="y")

    locations = _locations(request)
    message = invalid_request_message("publish_work", locations)

    assert "2 properties" in message
    assert locations[0]["count"] == "2"
    assert "zzz_unknown" not in message
    assert "aaa_unknown" not in message


def test_unknown_draft_envelope_key_keeps_the_envelope_recital() -> None:
    """An extra key on the draft object is an envelope defect, and the recital is right for it."""

    request = _obligation_request()
    request["event_drafts"][0]["zzz_unknown"] = "x"

    message = _message(request)

    assert "each event_drafts entry requires" in message
    assert "schema.name admits" in message


def test_an_unresolvable_family_still_names_admitted_families() -> None:
    """Zero or several surviving branches keep whole-tree scoring; the union must still be named."""

    request = _obligation_request()
    request["event_drafts"][0]["schema"] = {"name": 42, "version": "1.0.0"}

    locations = _locations(request)
    message = invalid_request_message("publish_work", locations)

    assert locations[0]["field"] == "/event_drafts/0/schema/name"
    assert locations[0]["reason"] != "extra_forbidden"
    assert "schema.name admits" in message
    assert _FAMILY in message


def test_a_bad_value_under_an_unallowlisted_payload_key_names_that_key() -> None:
    """The literal 14:01:55Z response: a value defect beneath a key the allowlist did not carry."""

    request = _with_payload_keys(source_refs=["not-an-event-id"])

    locations = _locations(request)
    message = invalid_request_message("publish_work", locations)

    assert locations[0]["field"].startswith("/event_drafts/0/payload/source_refs")
    assert locations[0]["reason"] != "extra_forbidden"
    assert "each event_drafts entry requires" not in message
    assert "not-an-event-id" not in message


@pytest.mark.anyio
async def test_safe_details_never_carries_the_internal_family_or_count_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def refuse(_runtime: object = bridge.BRIDGE_RUNTIME) -> object:
        raise AssertionError("a dry run must not reach the recovery oracle")

    monkeypatch.setattr(bridge, "ensure_service_client", refuse)
    runtime = bridge.build_bridge_runtime()

    request = {**_with_payload_keys(zzz_unknown="x"), "dry_run": True}
    result = await bridge.dispatch_publish_work(request, runtime)

    structured = cast(dict[str, object], result.structuredContent)
    error = cast(dict[str, object], structured["error"])
    assert error["code"] == PublicErrorCode.INVALID_REQUEST.value
    details = cast(dict[str, object], error["safe_details"])
    assert set(details) == {"continuation", "fields", "reasons"}
    assert details["reasons"] == ["extra_forbidden"]
    assert "family" not in details
    # `family_version` is an internal hint input like `family` and `count`, and travels the same
    # nowhere: it is not a SAFE_DETAIL_KEY and must not reach the caller as a detail key.
    assert "family_version" not in details
    assert "family_version" not in str(structured)
    await bridge.close_bridge_runtime(runtime)


def test_every_declared_schema_name_can_be_located_in_a_public_error() -> None:
    """A declared name outside the allowlist collapses its failure to an allowlisted parent."""

    from finishup.mcp.errors import (
        _DELIBERATELY_UNLOCATABLE_DECLARED,  # pyright: ignore[reportPrivateUsage]
        _SAFE_LOCATION_SEGMENTS,  # pyright: ignore[reportPrivateUsage]
        _schema_names,  # pyright: ignore[reportPrivateUsage]
    )

    required: set[str] = set()
    declared: set[str] = set()
    for tool in ("start", "publish_work", "check", "respond", "status", "receipt"):
        _schema_names(cast(Any, descriptor_for(tool).input_schema), required, declared)

    assert declared
    assert not declared - _SAFE_LOCATION_SEGMENTS - _DELIBERATELY_UNLOCATABLE_DECLARED
    # The escape hatch stays a reviewed decision rather than a growing exemption list.
    assert _DELIBERATELY_UNLOCATABLE_DECLARED == frozenset()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
