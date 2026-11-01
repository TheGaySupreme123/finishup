"""The post-commit projection window must never destroy an already-durable operation.

Every assertion here traces to the 2026-07-27 Codex dogfood, where a committed publication and a
pure ``status`` read both surfaced as ``response_projection_failed`` and exact same-``request_id``
replay reproduced the failure instead of the stored success.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Final, cast

import pytest

import finishup.application.service as service_module
import finishup.service.control_protocol as control_protocol_module
import finishup.service.daemon as daemon_module
from finishup.ports.control import ACCEPTED_STATE_KEYS, ControlError, ControlMethod
from finishup.protocol.canonical import JsonValue
from finishup.protocol.errors import PROTOCOL_REASON_CODES, SafeDetailValue

# Deliberately reaching for module privates: these are the exact internals inside the post-commit
# window, and the public surface cannot express "this internal never raises an unbounded error".
_replace_pointer = cast(
    Callable[[JsonValue, str, JsonValue], JsonValue],
    getattr(service_module, "_replace_pointer"),
)
_segments = cast(Callable[[str], tuple[str, ...]], getattr(service_module, "_segments"))
_READ_ONLY_METHODS = cast(frozenset[ControlMethod], getattr(daemon_module, "_READ_ONLY_METHODS"))
_PROJECTION_EXEMPT_METHODS = cast(
    frozenset[ControlMethod], getattr(daemon_module, "_PROJECTION_EXEMPT_METHODS")
)
_plain_wire_value = cast(
    Callable[[object], JsonValue], getattr(control_protocol_module, "_plain_wire_value")
)


def _body() -> JsonValue:
    return {
        "ok": True,
        "page": {"items": [{"summary": "text", "detail": "more"}], "next_cursor": None},
        "accepted_events": [{"summary": "one"}, {"summary": "two"}],
    }


def test_replace_pointer_rewrites_object_and_array_leaves() -> None:
    replaced = _replace_pointer(_body(), "/accepted_events/1/summary", {"omitted": True})
    assert isinstance(replaced, dict)
    events = replaced["accepted_events"]
    assert isinstance(events, tuple)
    first, second = events
    assert isinstance(first, dict) and first["summary"] == "one"
    assert isinstance(second, dict) and second["summary"] == {"omitted": True}


@pytest.mark.parametrize(
    "pointer",
    [
        # The exact shape `_pointer` fabricates when an origin pointer exceeds 256 bytes: a
        # synthetic `/leaf-N` that resolves nowhere in the body. Before this guard it raised a
        # bare KeyError inside the post-commit window.
        "/leaf-7",
        "/page/items/0/absent_field",
        "/page/absent_container/0/summary",
        # A non-numeric or out-of-range array segment must not raise ValueError from int() or
        # IndexError from the list lookup.
        "/accepted_events/not_an_index/summary",
        "/accepted_events/9/summary",
        "/accepted_events/01/summary",
    ],
)
def test_replace_pointer_rejects_unresolvable_pointers_with_a_bounded_error(pointer: str) -> None:
    with pytest.raises(ValueError) as excinfo:
        _replace_pointer(_body(), pointer, {"omitted": True})
    # Bounded and named: the daemon reclassifies anything it does not recognise, so an
    # unbounded KeyError/IndexError here becomes an unreplayable failure for the caller.
    assert str(excinfo.value) in {"projection_pointer_unresolved", "projection_pointer_invalid"}
    assert type(excinfo.value) is ValueError


def test_replace_pointer_rejects_a_pointer_that_is_not_a_pointer() -> None:
    with pytest.raises(ValueError, match="projection_pointer_invalid"):
        _segments("accepted_events/0/summary")


def test_read_only_methods_are_exactly_the_non_appending_ones() -> None:
    # `receipt` appends receipt_recorded and `check` appends check_recorded, so neither is a read.
    # Misclassifying either would tell a caller no durable state changed when it did.
    assert _READ_ONLY_METHODS == frozenset(
        {
            ControlMethod.STATUS,
            # Observation status is a bounded local read with no ledger append, so it gets the
            # same retry-on-projection-failure treatment as workflow status.
            ControlMethod.OBSERVATION_STATUS,
            ControlMethod.PRIVACY_GET_SETUP,
            ControlMethod.PRIVACY_GET_EFFECTIVE,
            # Names the disclosure proposals awaiting a decision; deciding one is a separate
            # confidential ceremony, so listing them appends nothing.
            ControlMethod.PRIVACY_PENDING_LIST,
            ControlMethod.PRIVACY_RECEIPTS_LIST,
            ControlMethod.PRIVACY_RECEIPTS_GET,
        }
    )
    assert ControlMethod.RECEIPT not in _READ_ONLY_METHODS
    assert ControlMethod.CHECK not in _READ_ONLY_METHODS
    assert ControlMethod.PUBLISH_WORK not in _READ_ONLY_METHODS
    # Repository privacy reads are projected; listing pending/receipt records stays structural.
    assert _READ_ONLY_METHODS - _PROJECTION_EXEMPT_METHODS == {
        ControlMethod.STATUS,
        ControlMethod.PRIVACY_GET_SETUP,
        ControlMethod.PRIVACY_GET_EFFECTIVE,
    }


def test_read_projection_failure_is_a_registered_retryable_reason() -> None:
    assert "read_projection_failed" in PROTOCOL_REASON_CODES
    error = ControlError("read_projection_failed", retryable=True)
    assert error.reason == "read_projection_failed"
    assert error.retryable is True


def test_read_projection_failure_must_be_retryable() -> None:
    # Repeating the read is the remedy, so a non-retryable variant would strand the caller.
    with pytest.raises(ValueError, match="read_projection_error_must_be_retryable"):
        ControlError("read_projection_failed")


_ACCEPTED_STATE: Final[Mapping[str, SafeDetailValue]] = MappingProxyType(
    {"count": 4, "head_digest": "sha256:" + "a" * 64, "sequence": 9}
)


def test_accepted_state_rides_the_post_commit_error() -> None:
    error = ControlError(
        "response_projection_failed", retryable=True, accepted_state=_ACCEPTED_STATE
    )
    assert dict(error.accepted_state) == dict(_ACCEPTED_STATE)
    assert tuple(sorted(error.accepted_state)) == ACCEPTED_STATE_KEYS


def test_accepted_state_defaults_to_empty() -> None:
    assert ControlError("response_projection_failed", retryable=True).accepted_state == {}
    assert ControlError("read_projection_failed", retryable=True).accepted_state == {}


def test_accepted_state_is_admitted_only_where_something_committed() -> None:
    # Attaching committed facts to a read, or to a failure that never appended, would assert a
    # durability that did not happen.
    with pytest.raises(ValueError, match="control_error_accepted_state_not_admitted"):
        ControlError("read_projection_failed", retryable=True, accepted_state=_ACCEPTED_STATE)
    with pytest.raises(ValueError, match="control_error_accepted_state_not_admitted"):
        ControlError("internal_error", accepted_state=_ACCEPTED_STATE)


def test_accepted_state_refuses_keys_the_allowlist_would_silently_drop() -> None:
    # normalize_safe_details drops unknown keys. Accepting the survivors would understate what
    # committed, so a rejected key fails loudly instead.
    with pytest.raises(ValueError, match="control_error_accepted_state_invalid"):
        ControlError(
            "response_projection_failed",
            retryable=True,
            accepted_state=cast(
                Mapping[str, SafeDetailValue],
                {**_ACCEPTED_STATE, "task_title": "not structural"},
            ),
        )


def test_accepted_state_survives_the_control_wire() -> None:
    original = ControlError(
        "response_projection_failed", retryable=True, accepted_state=_ACCEPTED_STATE
    )
    wire = _plain_wire_value(original)
    assert isinstance(wire, dict)
    assert wire["code"] == "response_projection_failed"
    assert wire["retryable"] is True
    assert wire["accepted_state"] == dict(_ACCEPTED_STATE)

    # The frame must round-trip, or the facts never reach the agent that needs them.
    restored = ControlError(
        cast(str, wire["code"]),
        retryable=cast(bool, wire["retryable"]),
        accepted_state=cast(Mapping[str, SafeDetailValue], wire["accepted_state"]),
    )
    assert dict(restored.accepted_state) == dict(_ACCEPTED_STATE)


def test_an_error_without_accepted_state_omits_the_field_entirely() -> None:
    wire = _plain_wire_value(ControlError("read_projection_failed", retryable=True))
    assert isinstance(wire, dict)
    assert "accepted_state" not in wire


_CORRELATION: Final = "err_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def test_correlation_id_defaults_to_none() -> None:
    assert ControlError("response_projection_failed", retryable=True).correlation_id is None
    assert ControlError("read_projection_failed", retryable=True).correlation_id is None
    assert ControlError("internal_error").correlation_id is None


def test_correlation_id_is_service_minted_structural_identity() -> None:
    error = ControlError(
        "response_projection_failed",
        retryable=True,
        accepted_state=_ACCEPTED_STATE,
        correlation_id=_CORRELATION,
    )
    assert error.correlation_id == _CORRELATION


def test_correlation_id_rejects_non_structural_values() -> None:
    with pytest.raises(ValueError, match="control_error_correlation_id_invalid"):
        ControlError("internal_error", correlation_id="not-an-err-id")
    with pytest.raises(ValueError, match="control_error_correlation_id_invalid"):
        ControlError(
            "response_projection_failed",
            retryable=True,
            correlation_id="req_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        )


def test_correlation_id_survives_the_control_wire() -> None:
    original = ControlError(
        "read_projection_failed",
        retryable=True,
        correlation_id=_CORRELATION,
    )
    wire = _plain_wire_value(original)
    assert isinstance(wire, dict)
    assert wire["code"] == "read_projection_failed"
    assert wire["correlation_id"] == _CORRELATION
    assert "accepted_state" not in wire

    restored = ControlError(
        cast(str, wire["code"]),
        retryable=cast(bool, wire["retryable"]),
        correlation_id=cast(str, wire["correlation_id"]),
    )
    assert restored.correlation_id == _CORRELATION


def test_an_error_without_correlation_id_omits_the_field_entirely() -> None:
    wire = _plain_wire_value(ControlError("response_projection_failed", retryable=True))
    assert isinstance(wire, dict)
    assert "correlation_id" not in wire
