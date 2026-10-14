from __future__ import annotations

from collections.abc import Iterator, Mapping
from enum import Enum
from typing import cast

import pytest
from hypothesis import given
from hypothesis import strategies as st

from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.ids import (
    IdKind,
    is_valid_id,
    new_id,
    safe_request_id_from,
    validate_actor_id,
    validate_id,
)
from property.strategies.identifiers import (
    strategy_invalid_ids,
    strategy_request_id_dicts,
    strategy_valid_ids,
)

_VALID_REQUEST_ID = "req_00000000-0000-4000-8000-000000000001"


class _HostileStr(str):
    def __len__(self) -> int:
        raise AssertionError("subclass length override was called")

    def __getitem__(self, key: object) -> str:
        raise AssertionError(f"subclass item override was called: {type(key).__name__}")


class _SpoofedStr:
    @property
    def __class__(  # pyright: ignore[reportIncompatibleMethodOverride]
        self,
    ) -> type[str]:
        return str


class _Coercible:
    def __str__(self) -> str:
        raise AssertionError("coercion was attempted")


class _RaisingGetMapping(Mapping[str, object]):
    def __getitem__(self, key: str) -> object:
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return iter(())

    def __len__(self) -> int:
        return 0

    def get(self, key: str, default: object = None, /) -> object:
        raise RuntimeError(f"request_id lookup failed for {key!r}")


class _SpoofedMapping:
    @property
    def __class__(  # pyright: ignore[reportIncompatibleMethodOverride]
        self,
    ) -> type[dict[str, object]]:
        return dict

    def get(self, key: object, default: object = None, /) -> object:
        raise AssertionError("spoofed mapping should not have been queried")


class _ForeignKind(str, Enum):  # noqa: UP042 - deliberately foreign str-valued Enum
    REQUEST = "request"


def _assert_reason(exc_info: pytest.ExceptionInfo[ProtocolValueError], reason: str) -> None:
    assert exc_info.value.reason_code == reason
    assert exc_info.value.args == (reason,)


@given(strategy_valid_ids)
def test_valid_ids_round_trip_by_kind(validated: tuple[IdKind, str]) -> None:
    kind, value = validated
    assert validate_id(kind, value) is value
    assert is_valid_id(kind, value)
    if kind is IdKind.ACTOR:
        assert validate_actor_id(value) is value


@given(strategy_invalid_ids)
def test_single_defect_mutations_fail(invalidated: tuple[IdKind, object, str]) -> None:
    kind, value, reason = invalidated
    with pytest.raises(ProtocolValueError) as exc_info:
        validate_id(kind, value)
    _assert_reason(exc_info, reason)


@given(strategy_request_id_dicts)
def test_safe_request_id_extraction_never_raises(arguments: object) -> None:
    result = safe_request_id_from(arguments)
    if result is not None:
        assert validate_id(IdKind.REQUEST, result) is result


def test_safe_request_id_requires_exact_builtin_str() -> None:
    assert safe_request_id_from({"request_id": _VALID_REQUEST_ID}) == _VALID_REQUEST_ID
    hostile_cases: tuple[object, ...] = (
        {"request_id": _HostileStr(_VALID_REQUEST_ID)},
        {"request_id": _SpoofedStr()},
        {"request_id": _Coercible()},
        {"request_id": "x" * 1000},
        _RaisingGetMapping(),
        _SpoofedMapping(),
        None,
        [],
        "not-a-mapping",
        {"request_id": "req_00000000-0000-4000-8000-00000000000\ud800"},
    )
    for arguments in hostile_cases:
        assert safe_request_id_from(arguments) is None


@given(st.one_of(st.none(), st.booleans(), st.integers(), st.text(), st.binary()))
def test_wrong_kind_programmer_defect_propagates(bad_kind: object) -> None:
    for operation in (
        lambda: new_id(cast(IdKind, bad_kind)),
        lambda: validate_id(cast(IdKind, bad_kind), _VALID_REQUEST_ID),
        lambda: is_valid_id(cast(IdKind, bad_kind), _VALID_REQUEST_ID),
    ):
        with pytest.raises(TypeError, match="^id_kind_wrong_type$"):
            operation()


def test_foreign_enum_kind_is_also_a_programmer_defect() -> None:
    with pytest.raises(TypeError, match="^id_kind_wrong_type$"):
        is_valid_id(cast(IdKind, _ForeignKind.REQUEST), _VALID_REQUEST_ID)
