"""``obligation_published`` 1.1.0: requested-item ``role`` and ``directory`` (issue #1002)."""

from __future__ import annotations

from typing import cast

import pytest

from yoetz.domain.events import (
    OBLIGATION_SCHEMA_VERSION,
    PAYLOAD_TYPES,
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    RequestedItem,
    RequestedItemKind,
    RequestedItemRole,
    decode_payload,
    encode_payload,
)
from yoetz.domain.values import freeze_json, obligation_id
from yoetz.protocol.canonical import JsonValue, canonical_encode
from yoetz.protocol.errors import ProtocolValueError
from yoetz.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance

_OBLIGATION = obligation_id("obl_10020000-0000-4000-8000-000000000001")
_V1_0 = EventSchema("obligation_published", "1.0.0")
_V1_1 = EventSchema("obligation_published", "1.1.0")


def _payload(*items: RequestedItem) -> ObligationPublishedPayload:
    return ObligationPublishedPayload(
        obligation_id=_OBLIGATION,
        description="Write the layout report from the layout spec.",
        evidence_expectation="The report exists and the check passes.",
        status=ObligationStatus.OPEN,
        requested_items=items,
    )


def test_version_constant_and_dispatch() -> None:
    assert OBLIGATION_SCHEMA_VERSION == "1.1.0"
    assert PAYLOAD_TYPES[_V1_0] is ObligationPublishedPayload
    assert PAYLOAD_TYPES[_V1_1] is ObligationPublishedPayload
    assert tuple(member.value for member in RequestedItemRole) == ("input", "output")


def test_role_and_directory_round_trip_under_1_1_0_only() -> None:
    payload = _payload(
        RequestedItem(RequestedItemKind.FILE, "/app/layout_spec.json", RequestedItemRole.INPUT),
        RequestedItem(RequestedItemKind.DIRECTORY, "/app/src", RequestedItemRole.OUTPUT),
        RequestedItem(RequestedItemKind.DIRECTORY, "/app/build"),
        RequestedItem(RequestedItemKind.COMMAND, "make test"),
    )
    wire = encode_payload(payload)
    items = cast(list[dict[str, JsonValue]], cast(dict[str, JsonValue], wire)["requested_items"])
    assert items[0] == {"item_kind": "file", "value": "/app/layout_spec.json", "role": "input"}
    assert items[2] == {"item_kind": "directory", "value": "/app/build"}
    assert "role" not in items[3]
    assert decode_payload(_V1_1, wire) == payload
    validate_schema_instance("obligation-published", "1.1.0", cast(JsonValue, wire))

    # The released 1.0.0 contract refuses both additions, in the domain codec and the schema.
    with pytest.raises(ProtocolValueError):
        decode_payload(_V1_0, wire)
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("obligation-published", "1.0.0", cast(JsonValue, wire))


@pytest.mark.parametrize(
    "item",
    [
        RequestedItem(RequestedItemKind.DIRECTORY, "/app/src"),
        RequestedItem(RequestedItemKind.FILE, "/app/out.json", RequestedItemRole.OUTPUT),
    ],
    ids=("directory", "role"),
)
def test_1_0_0_refuses_each_addition_alone(item: RequestedItem) -> None:
    wire = encode_payload(_payload(item))
    with pytest.raises(ProtocolValueError):
        decode_payload(_V1_0, wire)
    assert decode_payload(_V1_1, wire) == _payload(item)


def test_a_payload_without_additions_keeps_1_0_0_and_never_selects_1_1_0() -> None:
    payload = _payload(RequestedItem(RequestedItemKind.FILE, "report.json"))
    wire = encode_payload(payload)
    assert canonical_encode(wire) == canonical_encode(
        freeze_json(
            {
                "obligation_id": _OBLIGATION,
                "description": payload.description,
                "evidence_expectation": payload.evidence_expectation,
                "status": "open",
                "requested_items": [{"item_kind": "file", "value": "report.json"}],
            }
        )
    )
    assert decode_payload(_V1_0, wire) == payload
    assert not payload.requires_obligation_v1_1
    # The version is a pure function of the payload: 1.1.0 is only chosen for its features.
    with pytest.raises(ProtocolValueError):
        decode_payload(_V1_1, wire)


def test_unknown_role_and_item_fields_are_refused() -> None:
    base = {
        "obligation_id": _OBLIGATION,
        "description": "d",
        "evidence_expectation": "e",
        "status": "open",
    }
    for item in (
        {"item_kind": "file", "value": "a", "role": "both"},
        {"item_kind": "file", "value": "a", "purpose": "output"},
        {"item_kind": "folder", "value": "a"},
    ):
        with pytest.raises(ProtocolValueError):
            decode_payload(_V1_1, freeze_json({**base, "requested_items": [item]}))
    with pytest.raises(ProtocolValueError):
        RequestedItem(RequestedItemKind.FILE, "a", cast(RequestedItemRole, "both"))


def test_the_publish_event_draft_admits_1_1_0() -> None:
    draft: dict[str, JsonValue] = {
        "event_id": "evt_10020000-0000-4000-8000-000000000001",
        "schema": {"name": "obligation_published", "version": "1.1.0"},
        "occurred_at": "2026-01-01T00:00:00.000Z",
        "causal_parents": [],
        "artifact_refs": [],
        "evidence_refs": [],
        "payload": encode_payload(
            _payload(
                RequestedItem(RequestedItemKind.DIRECTORY, "src", RequestedItemRole.OUTPUT),
            )
        ),
    }
    validate_schema_instance("event-draft", "1.2.0", cast(JsonValue, freeze_json(draft)))


def test_the_status_obligations_item_shows_directory_and_role() -> None:
    from yoetz.protocol.models import StatusRequestedItemModel

    shown = StatusRequestedItemModel.model_validate(
        {"item_kind": "directory", "value": "src", "role": "output"}
    )
    assert (shown.item_kind, shown.role) == ("directory", "output")
    assert StatusRequestedItemModel.model_validate({"item_kind": "file", "value": "a"}).role is None
    assert StatusRequestedItemModel.optional_non_null_fields == frozenset({"role"})


def test_mcp_publish_work_advertises_both_obligation_versions() -> None:
    from yoetz.mcp.descriptors import descriptor_for
    from yoetz.protocol.canonical import canonical_encode as encode

    publish = encode(
        cast(JsonValue, freeze_json(dict(descriptor_for("publish_work").input_schema)))
    )
    for version in ("1.0.0", "1.1.0"):
        identity = (
            b'{"additionalProperties":false,"properties":{"name":{"const":"obligation_published"},'
            b'"version":{"const":"' + version.encode() + b'"}}'
        )
        assert identity in publish
    assert b'"directory"' in publish and b'"role"' in publish


@pytest.mark.parametrize(
    "kind",
    [
        RequestedItemKind.URL,
        RequestedItemKind.COMMAND,
        RequestedItemKind.CHANGE,
        RequestedItemKind.SOURCE,
    ],
)
def test_role_is_refused_on_items_that_name_no_path(kind: RequestedItemKind) -> None:
    with pytest.raises(ProtocolValueError):
        RequestedItem(kind, "x", RequestedItemRole.OUTPUT)
    wire = freeze_json(
        {
            "obligation_id": _OBLIGATION,
            "description": "d",
            "evidence_expectation": "e",
            "status": "open",
            "requested_items": [{"item_kind": kind.value, "value": "x", "role": "input"}],
        }
    )
    with pytest.raises(ProtocolValueError):
        decode_payload(_V1_1, wire)
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("obligation-published", "1.1.0", cast(JsonValue, wire))


def _acknowledged(reason: str | None) -> dict[str, JsonValue]:
    body: dict[str, JsonValue] = {
        "obligation_id": _OBLIGATION,
        "description": "Port the RTL to the new bus.",
        "evidence_expectation": "Simulation passes.",
        "status": "acknowledged_not_done",
    }
    if reason is not None:
        body["acknowledged_not_done_reason"] = reason
    return body


def test_acknowledged_not_done_requires_its_reason_and_1_1_0() -> None:
    wire = freeze_json(_acknowledged("The vendor simulator licence is unavailable."))
    payload = decode_payload(_V1_1, wire)
    assert isinstance(payload, ObligationPublishedPayload)
    assert payload.status is ObligationStatus.ACKNOWLEDGED_NOT_DONE
    assert payload.requires_obligation_v1_1
    assert encode_payload(payload) == wire
    validate_schema_instance("obligation-published", "1.1.0", cast(JsonValue, wire))

    # 1.0.0 refuses the status in the codec and in the frozen schema.
    with pytest.raises(ProtocolValueError):
        decode_payload(_V1_0, wire)
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("obligation-published", "1.0.0", cast(JsonValue, wire))

    # The reason is required for the status, refused when blank or over 4096 bytes...
    for reason in (None, "", "   \n\t", "é" * 2049):
        body = freeze_json(_acknowledged(reason))
        with pytest.raises(ProtocolValueError):
            decode_payload(_V1_1, body)
    for reason in (None, "", "   \n\t"):
        with pytest.raises(SchemaInstanceInvalid):
            validate_schema_instance(
                "obligation-published", "1.1.0", cast(JsonValue, freeze_json(_acknowledged(reason)))
            )
    # ...and forbidden with any other status.
    for status in ("open", "resolved"):
        body = {**_acknowledged("reason"), "status": status}
        if status == "resolved":
            body["resolution_evidence_refs"] = ["evd_10020000-0000-4000-8000-000000000001"]
        with pytest.raises(ProtocolValueError):
            decode_payload(_V1_1, freeze_json(body))
        with pytest.raises(SchemaInstanceInvalid):
            validate_schema_instance("obligation-published", "1.1.0", cast(JsonValue, body))
    with pytest.raises(ProtocolValueError):
        ObligationPublishedPayload(
            _OBLIGATION, "d", "e", ObligationStatus.OPEN, acknowledged_not_done_reason="why"
        )
    # Resolution refs stay reserved to resolved.
    with pytest.raises(ProtocolValueError):
        decode_payload(
            _V1_1,
            freeze_json(
                {
                    **_acknowledged("why"),
                    "resolution_evidence_refs": ["evd_10020000-0000-4000-8000-000000000001"],
                }
            ),
        )
