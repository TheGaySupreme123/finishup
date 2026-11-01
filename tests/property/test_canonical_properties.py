"""Property checks for canonical JSON parsing, encoding, and digest identity."""

from __future__ import annotations

from typing import cast

import pytest
from hypothesis import given
from hypothesis import strategies as st

from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.errors import ProtocolValueError
from property.strategies.json_values import (
    strategy_invalid_json_bytes,
    strategy_json_values,
    strategy_unicode_edge_strings,
)


def _assert_reason(exc_info: pytest.ExceptionInfo[ProtocolValueError], reason: str) -> None:
    assert exc_info.value.reason_code == reason
    assert exc_info.value.args == (reason,)


@given(strategy_json_values)
def test_parse_encode_round_trip(value: JsonValue) -> None:
    encoded = canonical_encode(value)
    reparsed = strict_json_parse(encoded)

    assert canonical_encode(reparsed) == encoded
    assert canonical_digest(reparsed) == canonical_digest(value)


@given(strategy_invalid_json_bytes)
def test_duplicate_keys_and_invalid_bytes_fail_first(invalid: tuple[bytes, str]) -> None:
    data, reason = invalid
    with pytest.raises(ProtocolValueError) as exc_info:
        strict_json_parse(data)
    _assert_reason(exc_info, reason)


@given(
    st.dictionaries(
        keys=strategy_unicode_edge_strings,
        values=strategy_json_values,
        min_size=2,
        max_size=6,
    ),
    st.data(),
)
def test_object_insertion_order_does_not_change_bytes(
    value: dict[str, JsonValue], data: st.DataObject
) -> None:
    items = list(value.items())
    permutation = data.draw(st.permutations(items))
    permuted = dict(permutation)

    assert canonical_encode(cast(JsonValue, value)) == canonical_encode(cast(JsonValue, permuted))
    assert canonical_digest(cast(JsonValue, value)) == canonical_digest(cast(JsonValue, permuted))


@given(st.lists(st.integers(min_value=-100, max_value=100), min_size=2, unique=True))
def test_array_order_remains_significant(values: list[int]) -> None:
    reversed_values = list(reversed(values))
    if values != reversed_values:
        assert canonical_encode(cast(JsonValue, values)) != canonical_encode(
            cast(JsonValue, reversed_values)
        )


@given(st.lists(strategy_json_values, max_size=8))
def test_list_and_tuple_arrays_have_identical_bytes(values: list[JsonValue]) -> None:
    assert canonical_encode(values) == canonical_encode(tuple(values))
