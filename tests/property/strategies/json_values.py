"""Hypothesis strategies for the restricted FinishUP JSON profile."""

from __future__ import annotations

from typing import Final, cast

from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy

from finishup.protocol.canonical import MAX_JSON_DEPTH, JsonValue

__all__ = [
    "strategy_invalid_json_bytes",
    "strategy_json_values",
    "strategy_unicode_edge_strings",
]

_MAX_SAFE_INTEGER: Final = 2**53 - 1
_VALID_CHARACTER = st.characters(codec="utf-8", blacklist_characters="\x00")
_VALID_STRING: SearchStrategy[str] = st.text(_VALID_CHARACTER, max_size=24)
_JSON_SCALARS: SearchStrategy[JsonValue] = cast(
    SearchStrategy[JsonValue],
    st.one_of(
        st.none(),
        st.booleans(),
        st.integers(min_value=-_MAX_SAFE_INTEGER, max_value=_MAX_SAFE_INTEGER),
        _VALID_STRING,
    ),
)


def _containers(children: SearchStrategy[JsonValue]) -> SearchStrategy[JsonValue]:
    arrays = st.one_of(
        st.lists(children, max_size=5),
        st.lists(children, max_size=5).map(tuple),
    )
    objects = st.dictionaries(_VALID_STRING, children, max_size=5)
    return cast(SearchStrategy[JsonValue], st.one_of(arrays, objects))


# ``max_leaves`` keeps generated examples comfortably below the contractual 64-container
# boundary; the exact boundary itself is covered with constructed unit vectors.
strategy_json_values: SearchStrategy[JsonValue] = st.recursive(
    _JSON_SCALARS,
    _containers,
    max_leaves=min(MAX_JSON_DEPTH, 20),
)


strategy_invalid_json_bytes: SearchStrategy[tuple[bytes, str]] = st.sampled_from(
    (
        (b'{"a":1,"a":2}', "duplicate_object_key"),
        (b'"\xff"', "invalid_utf8"),
        (b"\xef\xbb\xbf{}", "byte_order_mark_forbidden"),
        (b'"\\u0000"', "nul_byte_forbidden"),
        (b"1.0", "float_forbidden"),
        (b"-0", "float_forbidden"),
        (b"9007199254740992", "integer_out_of_safe_range"),
        (b'{"a":', "malformed_json"),
        (b"[" * 65 + b"0" + b"]" * 65, "nesting_too_deep"),
    )
)


strategy_unicode_edge_strings: SearchStrategy[str] = st.sampled_from(
    (
        "é",
        "e\u0301",
        "Å",
        "A\u030a",
        "a\u0323\u0301",
        "a\u0301\u0323",
        "שׁ",
        "שׂ",
        "😀",
        "𝌆",
        "ﬀ",
    )
)
