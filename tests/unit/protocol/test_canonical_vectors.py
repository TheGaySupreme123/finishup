"""Golden and inline vectors for the restricted canonical JSON contract."""

from __future__ import annotations

import base64
from collections import UserList
from typing import cast

import pytest

from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    canonical_integer_string,
    ensure_canonical_set,
    entry_digest,
    parse_canonical_integer_string,
    request_digest,
    strict_json_parse,
)
from finishup.protocol.errors import ProtocolValueError
from fixture_loader import JsonValue as FixtureJsonValue
from fixture_loader import load_fixture_json

_POSITIVE_FIXTURES = (
    "canonical/rfc8785-applicable.case.json",
    "canonical/restricted-json-positive.case.json",
)


def _fixture_dict(value: FixtureJsonValue) -> dict[str, FixtureJsonValue]:
    assert isinstance(value, dict)
    return value


def _fixture_list(value: FixtureJsonValue) -> list[FixtureJsonValue]:
    assert isinstance(value, list)
    return value


def _json_value(value: FixtureJsonValue) -> JsonValue:
    if value is None or type(value) in {bool, int, str}:
        return cast(None | bool | int | str, value)
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    assert isinstance(value, dict)
    return {key: _json_value(item) for key, item in value.items()}


def _assert_reason(exc_info: pytest.ExceptionInfo[ProtocolValueError], reason: str) -> None:
    assert exc_info.value.reason_code == reason
    assert exc_info.value.args == (reason,)


def _positive_vectors(path: str) -> list[dict[str, FixtureJsonValue]]:
    case = _fixture_dict(load_fixture_json(path))
    raw_vectors = _fixture_list(_fixture_dict(case["input"])["vectors"])
    return [_fixture_dict(vector) for vector in raw_vectors]


def _first_entry_preimage() -> dict[str, JsonValue]:
    case = _fixture_dict(load_fixture_json("canonical/accepted-entry-identity.case.json"))
    arrangement = _fixture_dict(_fixture_list(_fixture_dict(case["expected"])["arrangements"])[0])
    entry = _fixture_dict(_fixture_list(arrangement["entries"])[0])
    parsed = strict_json_parse(bytes.fromhex(cast(str, entry["digest_preimage_hex"])))
    assert isinstance(parsed, dict)
    return dict(parsed)


def test_canonical_bytes_match_golden_vectors() -> None:
    for path in _POSITIVE_FIXTURES:
        for vector in _positive_vectors(path):
            value = _json_value(vector["value"])
            assert canonical_encode(value) == bytes.fromhex(cast(str, vector["canonical_hex"]))

    worked: dict[str, JsonValue] = {
        "ﬀ": "bmp",
        "𝌆": "astral",
        "protocol": "yoetz.event",
        "writer": {"sequence": "12", "previous_entry_digest": "genesis"},
        "n": 42,
        "refs": ["evt_0d9254c1-031a-4e99-8bfe-a65ae8a28df8"],
    }
    assert (
        canonical_encode(worked)
        == (
            '{"n":42,"protocol":"yoetz.event","refs":'
            '["evt_0d9254c1-031a-4e99-8bfe-a65ae8a28df8"],'
            '"writer":{"previous_entry_digest":"genesis","sequence":"12"},'
            '"𝌆":"astral","ﬀ":"bmp"}'
        ).encode()
    )
    assert canonical_encode({"a": "line\nbreak", "b": "\x01"}) == (
        b'{"a":"line\\nbreak","b":"\\u0001"}'
    )


def test_digest_matches_reviewed_sha256() -> None:
    for path in _POSITIVE_FIXTURES:
        for vector in _positive_vectors(path):
            value = _json_value(vector["value"])
            expected = cast(str, vector["canonical_sha256"])
            assert canonical_digest(value) == expected
            assert expected.startswith("sha256:")
            assert expected[7:] == expected[7:].lower()

    assert canonical_digest({"a": "line\nbreak", "b": "\x01"}) == (
        "sha256:06efd62f5b85ba6f06b14beb4939be5733c4d75d2ea344d1dbeca87c9cb07912"
    )


def test_round_trip_idempotence() -> None:
    for vector in _positive_vectors("canonical/restricted-json-positive.case.json"):
        canonical_bytes = bytes.fromhex(cast(str, vector["canonical_hex"]))
        source_bytes = base64.b64decode(cast(str, vector["source_base64"]), validate=True)
        assert canonical_encode(strict_json_parse(source_bytes)) == canonical_bytes
        assert canonical_encode(strict_json_parse(canonical_bytes)) == canonical_bytes


def test_vector_loader_is_order_stable() -> None:
    forward = {
        path: cast(str, _fixture_dict(load_fixture_json(path))["fixture_id"])
        for path in _POSITIVE_FIXTURES
    }
    reverse = {
        path: cast(str, _fixture_dict(load_fixture_json(path))["fixture_id"])
        for path in reversed(_POSITIVE_FIXTURES)
    }
    assert forward == reverse
    assert forward == {
        "canonical/rfc8785-applicable.case.json": "CAN-001",
        "canonical/restricted-json-positive.case.json": "CAN-002",
    }


def test_utf16_and_normalization_vectors() -> None:
    case = _fixture_dict(load_fixture_json("canonical/utf16-property-order.case.json"))
    for raw_vector in _fixture_list(_fixture_dict(case["input"])["vectors"]):
        vector = _fixture_dict(raw_vector)
        members = _fixture_list(vector["source_members"])
        value: dict[str, JsonValue] = {}
        for raw_member in members:
            member = _fixture_dict(raw_member)
            value[cast(str, member["key"])] = _json_value(member["value"])
        assert canonical_encode(value).hex() == vector["canonical_hex"]
        assert canonical_digest(value) == vector["canonical_sha256"]

    case = _fixture_dict(load_fixture_json("canonical/unicode-normalization-distinct.case.json"))
    for raw_pair in _fixture_list(_fixture_dict(case["input"])["paired_strings"]):
        pair = _fixture_dict(raw_pair)
        left = _fixture_dict(pair["left"])
        right = _fixture_dict(pair["right"])
        left_value = _json_value(left["value"])
        right_value = _json_value(right["value"])
        assert canonical_encode(left_value).hex() == left["canonical_hex"]
        assert canonical_encode(right_value).hex() == right["canonical_hex"]
        assert canonical_encode(left_value) != canonical_encode(right_value)
        assert canonical_digest(left_value) != canonical_digest(right_value)


def test_request_and_entry_digests_match_reviewed_vectors() -> None:
    case = _fixture_dict(load_fixture_json("canonical/publication-request-identity.case.json"))
    expected_by_id = {
        cast(str, assertion["variant_id"]): cast(str, assertion["request_digest"])
        for assertion in (
            _fixture_dict(item)
            for item in _fixture_list(_fixture_dict(case["expected"])["assertions"])
        )
    }
    for raw_variant in _fixture_list(_fixture_dict(case["input"])["identity_variants"]):
        variant = _fixture_dict(raw_variant)
        assert (
            request_digest(_json_value(variant["identity"]))
            == expected_by_id[cast(str, variant["variant_id"])]
        )

    for raw_rejection in _fixture_list(_fixture_dict(case["input"])["fence_rejections"]):
        rejection = _fixture_dict(raw_rejection)
        with pytest.raises(ProtocolValueError) as exc_info:
            request_digest(_json_value(rejection["identity"]))
        _assert_reason(exc_info, cast(str, rejection["expected_reason"]))

    case = _fixture_dict(load_fixture_json("canonical/accepted-entry-identity.case.json"))
    for raw_arrangement in _fixture_list(_fixture_dict(case["expected"])["arrangements"]):
        arrangement = _fixture_dict(raw_arrangement)
        for raw_entry in _fixture_list(arrangement["entries"]):
            entry = _fixture_dict(raw_entry)
            preimage = strict_json_parse(bytes.fromhex(cast(str, entry["digest_preimage_hex"])))
            assert entry_digest(preimage) == entry["entry_digest"]


def test_non_json_rejection_paths_are_inline() -> None:
    with pytest.raises(ProtocolValueError) as exc_info:
        strict_json_parse(cast(bytes, "not bytes"))
    _assert_reason(exc_info, "input_not_bytes")

    for bad in (True, -1, 2**63):
        with pytest.raises(ProtocolValueError) as exc_info:
            canonical_integer_string(cast(int, bad))
        _assert_reason(exc_info, "integer_out_of_sqlite_range")

    with pytest.raises(ProtocolValueError) as exc_info:
        canonical_encode(cast(JsonValue, {1: "x"}))
    _assert_reason(exc_info, "object_key_not_string")

    with pytest.raises(ProtocolValueError) as exc_info:
        canonical_encode(cast(JsonValue, object()))
    _assert_reason(exc_info, "unsupported_json_type")

    preimage = _first_entry_preimage()
    invalid_preimages: list[JsonValue] = [
        [],
        {"protocol": "yoetz.event"},
        {**preimage, "entry_digest": "sha256:" + "0" * 64},
        {**preimage, "payload": {}},
        {**preimage, "protocol": "yoetz"},
    ]
    for invalid in invalid_preimages:
        with pytest.raises(ProtocolValueError) as exc_info:
            entry_digest(invalid)
        _assert_reason(exc_info, "not_an_accepted_envelope")


def test_integer_and_set_fixture_rejections() -> None:
    case = _fixture_dict(load_fixture_json("canonical/restricted-json-rejections.case.json"))
    for raw_vector in _fixture_list(_fixture_dict(case["input"])["helper_vectors"]):
        vector = _fixture_dict(raw_vector)
        reason = cast(str, vector["reason"])
        with pytest.raises(ProtocolValueError) as exc_info:
            if vector["helper"] == "parse_canonical_integer_string":
                parse_canonical_integer_string(cast(str, vector["input"]))
            else:
                ensure_canonical_set(cast(list[str], vector["input"]))
        _assert_reason(exc_info, reason)

    for unicode_digits in ("١", "１２", "२"):
        with pytest.raises(ProtocolValueError) as exc_info:
            parse_canonical_integer_string(unicode_digits)
        _assert_reason(exc_info, "noncanonical_integer_string")

    ensure_canonical_set([])
    ensure_canonical_set(("a", "b"))
    for values, reason in (
        (cast(list[str], "ab"), "unsupported_json_type"),
        (cast(list[str], UserList(["a", "b"])), "unsupported_json_type"),
        (cast(list[str], ["a", 1]), "set_member_not_ascii"),
        (["é"], "set_member_not_ascii"),
        (["a", "a"], "duplicate_set_member"),
        (["b", "a"], "unsorted_set_field"),
    ):
        with pytest.raises(ProtocolValueError) as exc_info:
            ensure_canonical_set(values)
        _assert_reason(exc_info, reason)
