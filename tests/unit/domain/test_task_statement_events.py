"""The task statement is persisted on exactly one schema per family (issue #908)."""

from __future__ import annotations

from typing import cast

import pytest

from yoetz.domain.events import (
    MAX_TASK_STATEMENT_BYTES,
    TASK_STATEMENT_EVENT_SCHEMAS,
    ClientKind,
    EventSchema,
    IntegrationKind,
    PlanPublishedPayload,
    PlanRevisedPayload,
    RuntimeProfile,
    SessionOpenedPayload,
    SessionResumedPayload,
    decode_payload,
    encode_payload,
)
from yoetz.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from yoetz.domain.task_statement import (
    TASK_STATEMENT_NOT_AUTHORIZED_GAP,
    TASK_STATEMENT_NOT_SUPPLIED_GAP,
    TASK_STATEMENT_UNAVAILABLE_GAP,
    specification_preflight,
    task_statement_gap_detail,
)
from yoetz.domain.values import Frontier, freeze_json, obligation_id
from yoetz.protocol.canonical import JsonValue
from yoetz.protocol.errors import ProtocolValueError
from yoetz.protocol.schemas import validate_schema_instance

_STATEMENT = "Under Ascii, Style.Truncate returns plain text without tail."
_OBLIGATION = obligation_id("obl_90800000-0000-4000-8000-000000000001")


def _payloads() -> tuple[
    tuple[
        str,
        str,
        str,
        SessionOpenedPayload | SessionResumedPayload | PlanPublishedPayload | PlanRevisedPayload,
    ],
    ...,
]:
    return (
        (
            "session_opened",
            "1.2.0",
            "1.1.0",
            SessionOpenedPayload(
                "termenv truncation",
                ClientKind.COOPERATIVE_AGENT,
                "0.1.0",
                IntegrationKind.COOPERATIVE_MCP,
                RuntimeProfile.TEST_FAKE,
                task_statement=_STATEMENT,
            ),
        ),
        (
            "session_resumed",
            "1.2.0",
            "1.1.0",
            SessionResumedPayload(
                ClientKind.COOPERATIVE_AGENT,
                "0.1.0",
                IntegrationKind.COOPERATIVE_MCP,
                RuntimeProfile.TEST_FAKE,
                Frontier(1, "sha256:" + "a" * 64),
                task_statement=_STATEMENT,
            ),
        ),
        (
            "plan_published",
            "1.1.0",
            "1.0.0",
            PlanPublishedPayload(1, "Agent plan", (_OBLIGATION,), task_statement=_STATEMENT),
        ),
        (
            "plan_revised",
            "1.1.0",
            "1.0.0",
            PlanRevisedPayload(2, 1, "User amended", "Agent plan", (), task_statement=_STATEMENT),
        ),
    )


@pytest.mark.parametrize("row", _payloads(), ids=lambda row: row[0])
def test_statement_round_trips_only_under_its_statement_bearing_version(
    row: tuple[str, str, str, object],
) -> None:
    family, version, older, payload = row
    schema = EventSchema(family, version)
    assert schema in TASK_STATEMENT_EVENT_SCHEMAS
    wire = encode_payload(cast(SessionOpenedPayload, payload))
    assert cast(dict[str, JsonValue], wire)["task_statement"] == _STATEMENT
    assert decode_payload(schema, wire) == payload
    if family != "session_resumed":
        # session-resumed's reviewed schema inherits a model-derived integer frontier that the
        # engine-authored wire never matched; only the field this version adds is new here.
        validate_schema_instance(family.replace("_", "-"), version, cast(JsonValue, wire))
    # The frozen older version never admits the field.
    with pytest.raises(ProtocolValueError):
        decode_payload(EventSchema(family, older), wire)
    without = {key: value for key, value in cast(dict[str, JsonValue], wire).items()}
    without.pop("task_statement")
    if family == "session_opened":
        # The unreleased session-opened 1.2.0 carries the statement as an optional field beside
        # the lineage metadata, so it still decodes without one.
        assert decode_payload(schema, freeze_json(without)) == SessionOpenedPayload(
            "termenv truncation",
            ClientKind.COOPERATIVE_AGENT,
            "0.1.0",
            IntegrationKind.COOPERATIVE_MCP,
            RuntimeProfile.TEST_FAKE,
        )
    else:
        # A version minted only for the statement is never chosen without it.
        with pytest.raises(ProtocolValueError):
            decode_payload(schema, freeze_json(without))


def test_statement_is_bounded_by_utf8_bytes_not_characters() -> None:
    fits = "é" * (MAX_TASK_STATEMENT_BYTES // 2)
    assert PlanPublishedPayload(1, "plan", (), task_statement=fits).task_statement == fits
    with pytest.raises(ProtocolValueError):
        PlanPublishedPayload(1, "plan", (), task_statement=fits + "é")
    with pytest.raises(ProtocolValueError):
        PlanPublishedPayload(1, "plan", (), task_statement="")


def test_gap_details_are_fixed_words_for_each_code() -> None:
    assert "did not receive the task statement" in cast(
        str, task_statement_gap_detail(TASK_STATEMENT_UNAVAILABLE_GAP)
    )
    assert "start.task_statement" in cast(
        str, task_statement_gap_detail(TASK_STATEMENT_NOT_SUPPLIED_GAP)
    )
    assert "yoetz --privacy" in cast(
        str, task_statement_gap_detail(TASK_STATEMENT_NOT_AUTHORIZED_GAP)
    )
    assert task_statement_gap_detail("content_unselected") is None


def test_full_specification_preflight_distinguishes_title_missing_and_withheld() -> None:
    selection = ReviewSelectionPolicy.for_profile(ReviewContextProfile.ASSISTED)
    title = specification_preflight(None, "task title", selection, required=True)
    assert title.status == "title_only"
    assert title.actionable is True
    assert title.gap == TASK_STATEMENT_NOT_SUPPLIED_GAP
    assert title.content_digest is not None

    missing = specification_preflight(None, None, selection, required=True)
    assert missing.status == "missing"
    assert missing.actionable is True
    assert missing.gap == TASK_STATEMENT_NOT_SUPPLIED_GAP

    legacy = ReviewSelectionPolicy.for_profile(
        ReviewContextProfile.ASSISTED, preset_version="1.1.0"
    )
    withheld = specification_preflight(None, None, legacy, required=True)
    assert withheld.status == "withheld"
    assert withheld.actionable is False
    assert withheld.gap == TASK_STATEMENT_NOT_AUTHORIZED_GAP


def test_an_older_service_contract_refuses_the_statement_instead_of_dropping_it() -> None:
    """Upgrade over a running older service (issue #908).

    A newer client's handshake already fails on the schema-manifest digest; even a start body
    that reached a released 0.2.5 service is refused by its closed start-request 1.0.0 schema,
    never accepted with the statement silently dropped. The unreleased 1.1.0 contract carries
    the field as an optional addition, so a body without it keeps its earlier shape.
    """

    from yoetz.protocol.schemas import SchemaInstanceInvalid

    wire = cast(
        JsonValue,
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": "req_90800000-0000-4000-8000-000000000002",
            "actor": {"actor_id": "harness:test", "actor_type": "harness"},
            "client": {"kind": "test_client", "version": "0.1.0", "integration": "local_cli"},
            "mode": "create",
            "task_title": "termenv truncation",
            "requested_view": "compact",
            "task_statement": _STATEMENT,
        },
    )
    validate_schema_instance("start-request", "1.1.0", wire)
    without = {key: value for key, value in cast(dict[str, JsonValue], wire).items()}
    without.pop("task_statement")
    validate_schema_instance("start-request", "1.0.0", cast(JsonValue, without))
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("start-request", "1.0.0", wire)
