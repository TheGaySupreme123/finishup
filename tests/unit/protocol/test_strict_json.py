"""Raw-byte JSON parsing and canonicalization fences."""

from __future__ import annotations

import base64
from typing import cast

import pytest

import finishup.protocol.canonical as canonical_module
from finishup.protocol.canonical import (
    MAX_JSON_DEPTH,
    JsonValue,
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.errors import ProtocolValueError
from fixture_loader import JsonValue as FixtureJsonValue
from fixture_loader import load_fixture_json


def _fixture_dict(value: FixtureJsonValue) -> dict[str, FixtureJsonValue]:
    assert isinstance(value, dict)
    return value


def _fixture_list(value: FixtureJsonValue) -> list[FixtureJsonValue]:
    assert isinstance(value, list)
    return value


def _assert_reason(exc_info: pytest.ExceptionInfo[ProtocolValueError], reason: str) -> None:
    assert exc_info.value.reason_code == reason
    assert exc_info.value.args == (reason,)


def _nested_array(depth: int) -> JsonValue:
    value: JsonValue = 0
    for _ in range(depth):
        value = [value]
    return value


def test_parse_accepts_canonical_vectors() -> None:
    case = _fixture_dict(load_fixture_json("canonical/restricted-json-positive.case.json"))
    for raw_vector in _fixture_list(_fixture_dict(case["input"])["vectors"]):
        vector = _fixture_dict(raw_vector)
        source = base64.b64decode(cast(str, vector["source_base64"]), validate=True)
        expected = bytes.fromhex(cast(str, vector["canonical_hex"]))
        assert canonical_encode(strict_json_parse(source)) == expected
        assert canonical_encode(strict_json_parse(expected)) == expected


def test_parse_snapshots_bytearray_input(monkeypatch: pytest.MonkeyPatch) -> None:
    source = bytearray(b'["keep"]')
    real_loads = canonical_module.json.loads

    def mutate_after_snapshot(
        data: str | bytes | bytearray, *args: object, **kwargs: object
    ) -> object:
        source[:] = b'["mutated"]'
        return real_loads(data, *args, **kwargs)

    monkeypatch.setattr(canonical_module.json, "loads", mutate_after_snapshot)
    assert strict_json_parse(source) == ["keep"]
    assert source == bytearray(b'["mutated"]')


def test_parse_rejects_reviewed_wire_vectors_with_exact_reasons() -> None:
    case = _fixture_dict(load_fixture_json("canonical/restricted-json-rejections.case.json"))
    vectors = _fixture_list(_fixture_dict(case["input"])["parser_vectors"])
    for raw_vector in vectors:
        vector = _fixture_dict(raw_vector)
        source = base64.b64decode(cast(str, vector["bytes_base64"]), validate=True)
        with pytest.raises(ProtocolValueError) as exc_info:
            strict_json_parse(source)
        _assert_reason(exc_info, cast(str, vector["expected_reason"]))


def test_parse_rejects_duplicate_keys_and_non_utf8() -> None:
    for source, reason in (
        (b'{"a":1,"a":2}', "duplicate_object_key"),
        (b'"\xff"', "invalid_utf8"),
        (b"\xef\xbb\xbf{}", "byte_order_mark_forbidden"),
        (b'"\\u0000"', "nul_byte_forbidden"),
        (b"\x00", "nul_byte_forbidden"),
        (b"", "malformed_json"),
        (b"{} trailing", "malformed_json"),
    ):
        with pytest.raises(ProtocolValueError) as exc_info:
            strict_json_parse(source)
        _assert_reason(exc_info, reason)


def test_parse_rejects_float_and_negative_zero() -> None:
    for source in (b"0.0", b"1e0", b"-0", b"NaN", b"Infinity", b"-Infinity"):
        with pytest.raises(ProtocolValueError) as exc_info:
            strict_json_parse(source)
        _assert_reason(exc_info, "float_forbidden")


def test_parse_rejects_lone_surrogates_and_overflow() -> None:
    for source, reason in (
        (b'"\\ud800"', "lone_surrogate"),
        (b'"\\udfff"', "lone_surrogate"),
        (b"9007199254740992", "integer_out_of_safe_range"),
        (b"-9007199254740992", "integer_out_of_safe_range"),
    ):
        with pytest.raises(ProtocolValueError) as exc_info:
            strict_json_parse(source)
        _assert_reason(exc_info, reason)


def test_maximum_container_depth_is_exact() -> None:
    accepted_bytes = b"[" * MAX_JSON_DEPTH + b"0" + b"]" * MAX_JSON_DEPTH
    rejected_bytes = b"[" * (MAX_JSON_DEPTH + 1) + b"0" + b"]" * (MAX_JSON_DEPTH + 1)
    assert strict_json_parse(accepted_bytes) == _nested_array(MAX_JSON_DEPTH)
    assert canonical_encode(_nested_array(MAX_JSON_DEPTH)) == accepted_bytes
    with pytest.raises(ProtocolValueError) as exc_info:
        strict_json_parse(rejected_bytes)
    _assert_reason(exc_info, "nesting_too_deep")


def test_canonical_encode_is_stable() -> None:
    first = {"ﬀ": 3, "a": 1, "𝌆": 2}
    second = {"𝌆": 2, "ﬀ": 3, "a": 1}
    assert canonical_encode(first) == canonical_encode(second)
    assert canonical_encode([1, 2]) != canonical_encode([2, 1])
    assert canonical_encode("é") != canonical_encode("e\u0301")


class _SpoofedMapping:
    @property
    def __class__(  # pyright: ignore[reportIncompatibleMethodOverride]
        self,
    ) -> type[dict[str, object]]:
        return dict


def test_canonical_encode_rejects_unsupported_python_types() -> None:
    for value in (object(), range(3), {1, 2}, _SpoofedMapping()):
        with pytest.raises(ProtocolValueError) as exc_info:
            canonical_encode(cast(JsonValue, value))
        _assert_reason(exc_info, "unsupported_json_type")
