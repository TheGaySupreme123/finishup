from __future__ import annotations

import importlib
import importlib.util
from collections.abc import Iterator, Mapping
from enum import Enum
from types import MappingProxyType
from typing import cast

import pytest

import yoetz.protocol.ids as ids_module
from fixture_loader import JsonValue, load_fixture_json
from yoetz.protocol.errors import PROTOCOL_REASON_CODES, ProtocolValueError
from yoetz.protocol.ids import (
    ACTOR_ID_PATTERN,
    ID_TOTAL_LENGTH,
    PREFIX_BY_KIND,
    IdKind,
    is_valid_id,
    new_id,
    safe_request_id_from,
    validate_actor_id,
    validate_id,
)

_VALID_REQUEST_ID = "req_00000000-0000-4000-8000-000000000001"

_EXPECTED_KINDS: tuple[tuple[str, str, str], ...] = (
    ("REQUEST", "request", "req_"),
    ("INSTALLATION", "installation", "ins_"),
    ("TASK", "task", "tsk_"),
    ("SESSION", "session", "ses_"),
    ("WRITER", "writer", "wri_"),
    ("EVENT", "event", "evt_"),
    ("OBLIGATION", "obligation", "obl_"),
    ("CLAIM", "claim", "clm_"),
    ("ACTION", "action", "act_"),
    ("RESULT", "result", "res_"),
    ("EVIDENCE", "evidence", "evd_"),
    ("FINDING", "finding", "fnd_"),
    ("OBJECT", "object", "obj_"),
    ("RECEIPT", "receipt", "rcp_"),
    ("CORRELATION", "correlation", "err_"),
    ("SEMANTIC_JOB", "semantic_job", "job_"),
    ("SEMANTIC_ATTEMPT", "semantic_attempt", "att_"),
    ("MAINTENANCE_PIN", "maintenance_pin", "pin_"),
    ("SERVICE_INSTANCE", "service_instance", "svc_"),
    ("CONTROL_RPC", "control_rpc", "rpc_"),
    ("PRIVACY_POLICY", "privacy_policy", "pvy_"),
    ("PRIVACY_SETUP_SESSION", "privacy_setup_session", "psw_"),
    ("PRIVACY_PROPOSAL", "privacy_proposal", "ppr_"),
    ("OUTBOUND_CASE", "outbound_case", "cas_"),
    ("EGRESS_AUTHORIZATION", "egress_authorization", "aut_"),
    ("EGRESS_DISPATCH", "egress_dispatch", "dsp_"),
    ("EGRESS_RECEIPT", "egress_receipt", "egr_"),
    ("ACTOR", "actor", "agt_"),
    ("PROJECT", "project", "prj_"),
)

_OWNED_REASONS = frozenset(
    {
        "actor_id_malformed",
        "actor_id_not_generated",
        "id_malformed_uuid",
        "id_not_ascii",
        "id_uuid_not_version_4",
        "id_uuid_wrong_variant",
        "id_wrong_length",
        "id_wrong_prefix",
        "id_wrong_type",
    }
)


class _ForeignKind(str, Enum):  # noqa: UP042 - deliberately foreign str-valued Enum
    REQUEST = "request"


class _HostileStr(str):
    def __len__(self) -> int:
        raise AssertionError("subclass length override was called")

    def __getitem__(self, key: object) -> str:
        raise AssertionError(f"subclass item override was called: {type(key).__name__}")

    def __iter__(self) -> Iterator[str]:
        raise AssertionError("subclass iterator override was called")

    def encode(self, *args: object, **kwargs: object) -> bytes:
        raise AssertionError("subclass encode override was called")

    def startswith(self, *args: object, **kwargs: object) -> bool:
        raise AssertionError("subclass startswith override was called")


class _SpoofedStr:
    @property
    def __class__(  # pyright: ignore[reportIncompatibleMethodOverride]
        self,
    ) -> type[str]:
        return str


class _SpoofedKind:
    @property
    def __class__(  # pyright: ignore[reportIncompatibleMethodOverride]
        self,
    ) -> type[IdKind]:
        return IdKind


class _RaisingClass:
    @property
    def __class__(  # pyright: ignore[reportIncompatibleMethodOverride]
        self,
    ) -> type[object]:
        raise KeyboardInterrupt("class inspection")


class _Coercible:
    def __str__(self) -> str:
        raise AssertionError("coercion was attempted")


class _RaisingGetMapping(Mapping[object, object]):
    def __getitem__(self, key: object) -> object:
        raise KeyError(key)

    def __iter__(self) -> Iterator[object]:
        return iter(())

    def __len__(self) -> int:
        return 0

    def get(self, key: object, default: object = None, /) -> object:
        raise KeyboardInterrupt(f"lookup failed for {type(key).__name__}")


class _SpoofedMapping:
    @property
    def __class__(  # pyright: ignore[reportIncompatibleMethodOverride]
        self,
    ) -> type[dict[object, object]]:
        return dict

    def get(self, key: object, default: object = None, /) -> object:
        return _VALID_REQUEST_ID


def _assert_reason(exc_info: pytest.ExceptionInfo[ProtocolValueError], reason: str) -> None:
    assert exc_info.value.reason_code == reason
    assert exc_info.value.args == (reason,)


def _as_mapping(value: JsonValue) -> dict[str, JsonValue]:
    assert isinstance(value, dict)
    return value


def _as_list(value: JsonValue) -> list[JsonValue]:
    assert isinstance(value, list)
    return value


def test_new_id_kind_matrix(monkeypatch: pytest.MonkeyPatch) -> None:
    assert IdKind.__bases__ == (str, Enum)
    assert (
        tuple((kind.name, kind.value, PREFIX_BY_KIND[kind]) for kind in IdKind) == _EXPECTED_KINDS
    )
    assert len(IdKind) == 29
    assert ID_TOTAL_LENGTH == 40
    assert ACTOR_ID_PATTERN == r"^[A-Za-z0-9._:-]{1,128}$"
    assert isinstance(PREFIX_BY_KIND, MappingProxyType)
    assert not hasattr(ids_module, "_PREFIX_BY_KIND_MUTABLE")
    with pytest.raises(TypeError):
        cast(dict[IdKind, str], PREFIX_BY_KIND)[IdKind.REQUEST] = "bad_"

    calls: list[int] = []

    def fixed_random(size: int) -> bytes:
        calls.append(size)
        return bytes(range(16))

    monkeypatch.setattr(ids_module.os, "urandom", fixed_random)
    for kind in IdKind:
        if kind is IdKind.ACTOR:
            with pytest.raises(ProtocolValueError) as exc_info:
                new_id(kind)
            _assert_reason(exc_info, "actor_id_not_generated")
            continue
        generated = new_id(kind)
        assert len(generated) == ID_TOTAL_LENGTH
        assert generated.startswith(PREFIX_BY_KIND[kind])
        assert generated[18] == "4"
        assert generated[23] in "89ab"
        assert validate_id(kind, generated) == generated
    assert calls == [16] * 28


def test_generation_forces_version_and_variant_distribution() -> None:
    variant_chars: set[str] = set()
    for _ in range(10_000):
        generated = new_id(IdKind.REQUEST)
        assert generated[18] == "4"
        assert generated[23] in "89ab"
        assert generated == generated.lower()
        variant_chars.add(generated[23])
    assert variant_chars == set("89ab")


def test_validate_id_rejects_bad_shapes_from_frozen_vectors() -> None:
    fixture = _as_mapping(load_fixture_json("canonical/identifiers.case.json"))
    input_value = _as_mapping(fixture["input"])
    valid_vectors = _as_list(input_value["valid_vectors"])
    # The original identifier vectors remain frozen; the project kind is covered by the
    # additive assertion below so the historical fixture does not need to be rewritten.
    assert len(valid_vectors) == 28
    for raw_vector in valid_vectors:
        vector = _as_mapping(raw_vector)
        kind = IdKind(cast(str, vector["kind"]))
        value = cast(str, vector["value"])
        assert validate_id(kind, value) is value
        assert is_valid_id(kind, value)
    project_value = "prj_00000000-0000-4000-8000-000000000001"
    assert validate_id(IdKind.PROJECT, project_value) is project_value
    assert is_valid_id(IdKind.PROJECT, project_value)

    negative_vectors = _as_list(input_value["negative_vectors"])
    seen_reasons: set[str] = set()
    for raw_vector in negative_vectors:
        vector = _as_mapping(raw_vector)
        kind = IdKind(cast(str, vector["kind"]))
        value: object = vector["value"]
        expected_reason = cast(str, vector["detail_category"])
        with pytest.raises(ProtocolValueError) as exc_info:
            validate_id(kind, value)
        _assert_reason(exc_info, expected_reason)
        assert not is_valid_id(kind, value)
        seen_reasons.add(expected_reason)
    assert seen_reasons == _OWNED_REASONS - {"actor_id_not_generated"}


def test_validate_id_failure_order_is_bounded() -> None:
    short_non_ascii = "req_" + "a" * 34 + "é"
    assert len(short_non_ascii) == 39
    with pytest.raises(ProtocolValueError) as length_exc:
        validate_id(IdKind.REQUEST, short_non_ascii)
    _assert_reason(length_exc, "id_wrong_length")

    non_ascii = "req_" + "a" * 35 + "é"
    assert len(non_ascii) == ID_TOTAL_LENGTH
    with pytest.raises(ProtocolValueError) as ascii_exc:
        validate_id(IdKind.REQUEST, non_ascii)
    _assert_reason(ascii_exc, "id_not_ascii")

    with pytest.raises(ProtocolValueError) as prefix_exc:
        validate_id(IdKind.REQUEST, "ses_00000000-0000-5000-7000-000000000001")
    _assert_reason(prefix_exc, "id_wrong_prefix")


def test_validate_id_is_kind_specific() -> None:
    generated = {kind: new_id(kind) for kind in IdKind if kind is not IdKind.ACTOR}
    non_actor_kinds = tuple(generated)
    for index, kind in enumerate(non_actor_kinds):
        other = non_actor_kinds[(index + 1) % len(non_actor_kinds)]
        with pytest.raises(ProtocolValueError) as exc_info:
            validate_id(other, generated[kind])
        _assert_reason(exc_info, "id_wrong_prefix")


def test_direct_validation_accepts_real_str_subclasses_without_overrides() -> None:
    request_value = _HostileStr(_VALID_REQUEST_ID)
    assert validate_id(IdKind.REQUEST, request_value) is request_value
    assert is_valid_id(IdKind.REQUEST, request_value)
    actor_value = _HostileStr("agt_hostile-subclass")
    assert validate_actor_id(actor_value) is actor_value
    assert validate_id(IdKind.ACTOR, actor_value) is actor_value

    for impersonator in (_SpoofedStr(), _RaisingClass()):
        with pytest.raises(ProtocolValueError) as exc_info:
            validate_id(IdKind.REQUEST, impersonator)
        _assert_reason(exc_info, "id_wrong_type")


def test_safe_request_id_from_is_non_raising_and_exact() -> None:
    assert safe_request_id_from({"request_id": _VALID_REQUEST_ID}) == _VALID_REQUEST_ID
    hostile_arguments: tuple[object, ...] = (
        None,
        [],
        {},
        {"request_id": None},
        {"request_id": _Coercible()},
        {"request_id": _HostileStr(_VALID_REQUEST_ID)},
        {"request_id": "x" * 1_000_000},
        {"request_id": "req_" + "a" * 35 + "\ud800"},
        _RaisingGetMapping(),
        _SpoofedMapping(),
        _RaisingClass(),
    )
    for arguments in hostile_arguments:
        assert safe_request_id_from(arguments) is None


def test_actor_prefix_is_convention_only() -> None:
    for value in ("agt_api_mapper", "agt_parent", "ci-bot.7", "a", "x" * 128):
        assert validate_actor_id(value) == value
        assert validate_id(IdKind.ACTOR, value) == value
    for value, reason in (
        ("", "actor_id_malformed"),
        ("actor has spaces", "actor_id_malformed"),
        ("é", "actor_id_malformed"),
        ("x" * 129, "id_wrong_length"),
    ):
        with pytest.raises(ProtocolValueError) as exc_info:
            validate_actor_id(value)
        _assert_reason(exc_info, reason)


@pytest.mark.parametrize(
    "bad_kind",
    ["request", _ForeignKind.REQUEST, _SpoofedKind()],
    ids=("raw-token", "foreign-enum", "spoofed-class"),
)
def test_wrong_kind_is_programmer_defect(bad_kind: object) -> None:
    for operation in (
        lambda: new_id(cast(IdKind, bad_kind)),
        lambda: validate_id(cast(IdKind, bad_kind), _VALID_REQUEST_ID),
        lambda: is_valid_id(cast(IdKind, bad_kind), _VALID_REQUEST_ID),
    ):
        with pytest.raises(TypeError, match="^id_kind_wrong_type$"):
            operation()


def test_wrong_kind_fails_before_randomness_or_value_inspection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_random(_: int) -> bytes:
        raise AssertionError("randomness was read")

    monkeypatch.setattr(ids_module.os, "urandom", forbidden_random)
    with pytest.raises(TypeError, match="^id_kind_wrong_type$"):
        new_id(cast(IdKind, "request"))
    with pytest.raises(TypeError, match="^id_kind_wrong_type$"):
        validate_id(cast(IdKind, "request"), _HostileStr(_VALID_REQUEST_ID))


def test_no_identifier_parse_surface() -> None:
    assert tuple(ids_module.__all__) == (
        "ACTOR_ID_PATTERN",
        "OPAQUE_ITEM_ID_PATTERN",
        "ID_TOTAL_LENGTH",
        "PREFIX_BY_KIND",
        "IdKind",
        "is_valid_id",
        "new_id",
        "safe_request_id_from",
        "validate_actor_id",
        "validate_opaque_item_id",
        "validate_id",
    )
    for forbidden in (
        "parse_id",
        "kind_from_id",
        "id_kind_from_prefix",
        "PREFIX_TO_KIND",
        "KIND_BY_PREFIX",
    ):
        assert not hasattr(ids_module, forbidden)


def test_id_reasons_are_exact_central_registry_subset() -> None:
    before = PROTOCOL_REASON_CODES
    assert _OWNED_REASONS <= before
    assert "id_kind_wrong_type" not in before
    for sibling in (
        "yoetz.protocol.canonical",
        "yoetz.protocol.coverage",
        "yoetz.protocol.schemas",
    ):
        if importlib.util.find_spec(sibling) is None:
            continue
        importlib.import_module(sibling)
        assert ids_module.ProtocolValueError is ProtocolValueError
        assert PROTOCOL_REASON_CODES is before
