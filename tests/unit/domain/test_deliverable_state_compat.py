"""Deliverable states written by intermediate tb4n5 builds still decode (read, never dropped).

Commit 857a712de recorded ``undeclared_references_created_in_task: true`` on ``check_recorded``
1.4.0 deliverable states; 38ecb467d removed the field from the closed decoder, so an intact
historical payload failed as ``unknown_payload_field`` and SQLite recovery mapped it to
``STORAGE_CORRUPT``. The field is read-compatible again: decoded, re-encoded byte-identically, and
never produced or consulted for disclosure.
"""

from __future__ import annotations

from typing import cast

import pytest

from finishup.domain.events import DeliverableState, EventSchema, decode_payload, encode_payload
from finishup.domain.values import JsonValue as DomainJsonValue
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.schemas import validate_schema_instance
from unit.application import test_undeclared_names_never_egress as named_checks

_SCHEMA = EventSchema("check_recorded", "1.4.0")


def _historical_wire() -> dict[str, JsonValue]:
    """A check payload exactly as 857a712de wrote it: the flag, without the later ambiguity count."""

    row, _digest = named_checks._check_row(with_names=True)  # pyright: ignore[reportPrivateUsage]
    wire = cast(dict[str, JsonValue], strict_json_parse(canonical_encode(row.payload)))
    state = cast(dict[str, JsonValue], cast(list[JsonValue], wire["deliverable_states"])[0])
    state.pop("undeclared_reference_ambiguous", None)
    state["undeclared_references_created_in_task"] = True
    return wire


def test_a_check_payload_from_the_intermediate_build_decodes_and_round_trips() -> None:
    wire = _historical_wire()
    decoded = decode_payload(_SCHEMA, cast(DomainJsonValue, wire))
    assert canonical_encode(encode_payload(decoded)) == canonical_encode(wire)
    validate_schema_instance("check-recorded", "1.4.0", cast(JsonValue, wire))


def test_the_flag_is_kept_on_the_state_and_new_states_never_emit_it() -> None:
    state_wire = cast(
        dict[str, JsonValue], cast(list[JsonValue], _historical_wire()["deliverable_states"])[0]
    )
    state = DeliverableState.from_wire(state_wire)
    assert state.undeclared_references_created_in_task is True
    assert canonical_encode(cast(JsonValue, state.as_wire())) == canonical_encode(state_wire)

    fresh = DeliverableState.from_wire(
        {
            key: value
            for key, value in state_wire.items()
            if key != "undeclared_references_created_in_task"
        }
    )
    assert fresh.undeclared_references_created_in_task is False
    assert "undeclared_references_created_in_task" not in fresh.as_wire()


def test_a_false_or_orphan_flag_is_still_refused() -> None:
    state_wire = cast(
        dict[str, JsonValue], cast(list[JsonValue], _historical_wire()["deliverable_states"])[0]
    )
    with pytest.raises(ProtocolValueError):
        DeliverableState.from_wire(dict(state_wire, undeclared_references_created_in_task=False))
    orphan = {
        key: value
        for key, value in state_wire.items()
        if key not in {"undeclared_references", "undeclared_reference_count"}
    }
    with pytest.raises(ProtocolValueError):
        DeliverableState.from_wire(orphan)
