"""Issue #582: ``SemanticProvenance.fallback_from`` names the primary a fallback stood in for."""

from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest

from finishup.domain.findings import (
    SemanticFallbackOrigin,
    SemanticProvenance,
    semantic_fallback_origin_to_json,
    semantic_provenance_from_json,
    semantic_provenance_to_json,
)
from finishup.domain.values import JsonObject
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.models import SemanticReason
from finishup.protocol.schemas import validate_schema_instance
from unit.domain.test_findings import _provenance  # pyright: ignore[reportPrivateUsage]


def _origin(**overrides: object) -> SemanticFallbackOrigin:
    values: dict[str, object] = {
        "provider": "openai-codex",
        "endpoint_profile_id": "codex-chatgpt-subscription",
        "endpoint_profile_version": "1.0.0",
        "model": "gpt-5.6-sol",
        "attempted_count": 2,
        "reason": SemanticReason.TRANSPORT_UNAVAILABLE,
    }
    values.update(overrides)
    return SemanticFallbackOrigin(**values)  # type: ignore[arg-type]


def _reason_of(factory: object) -> str:
    assert callable(factory)
    with pytest.raises(ProtocolValueError) as caught:
        factory()
    return caught.value.reason_code


def test_origin_accepts_the_bounded_count_and_a_closed_reason() -> None:
    origin = _origin(attempted_count=0, reason=SemanticReason.CREDENTIAL_UNAVAILABLE)
    assert origin.attempted_count == 0
    assert origin.reason is SemanticReason.CREDENTIAL_UNAVAILABLE
    assert _origin(attempted_count=8).attempted_count == 8
    assert _origin() == _origin()


def test_origin_rejects_an_out_of_range_count_or_unclosed_identity() -> None:
    for count in (-1, 9, "2", 2.0, True):
        assert _reason_of(lambda: _origin(attempted_count=count)) == (
            "invalid_semantic_fallback_origin"
        )
    assert _reason_of(lambda: _origin(reason="transport_unavailable")) == (
        "invalid_semantic_fallback_origin"
    )
    assert _reason_of(lambda: _origin(provider="Not Valid")) == "invalid_semantic_fallback_origin"
    assert _reason_of(lambda: _origin(endpoint_profile_id="")) == "invalid_semantic_fallback_origin"
    assert _reason_of(lambda: _origin(endpoint_profile_version="1.0")) == (
        "invalid_semantic_fallback_origin"
    )
    assert _reason_of(lambda: _origin(model="")) == "invalid_semantic_fallback_origin"


def test_provenance_carries_an_origin_and_defaults_to_none() -> None:
    assert _provenance().fallback_from is None
    served_by_fallback = replace(_provenance(), fallback_from=_origin())
    assert served_by_fallback.fallback_from == _origin()


def test_provenance_rejects_a_foreign_object_as_its_origin() -> None:
    assert (
        _reason_of(
            lambda: replace(_provenance(), fallback_from=cast(SemanticFallbackOrigin, object()))
        )
        == "invalid_semantic_fallback_origin"
    )


def test_json_omits_the_key_when_none_and_round_trips_when_set() -> None:
    plain = semantic_provenance_to_json(_provenance())
    assert "fallback_from" not in plain
    assert semantic_provenance_from_json(plain).fallback_from is None

    provenance = replace(_provenance(), fallback_from=_origin())
    encoded = semantic_provenance_to_json(provenance)
    assert encoded["fallback_from"] == semantic_fallback_origin_to_json(_origin())
    assert encoded["fallback_from"] == JsonObject(
        (
            ("provider", "openai-codex"),
            ("endpoint_profile_id", "codex-chatgpt-subscription"),
            ("endpoint_profile_version", "1.0.0"),
            ("model", "gpt-5.6-sol"),
            ("attempted_count", "2"),
            ("reason", "transport_unavailable"),
        )
    )
    decoded = semantic_provenance_from_json(encoded)
    assert decoded == provenance
    assert type(decoded.fallback_from) is SemanticFallbackOrigin
    assert canonical_encode(cast(JsonValue, encoded)) == canonical_encode(
        cast(JsonValue, semantic_provenance_to_json(decoded))
    )
    # The single-endpoint encoding is byte-identical to before: the only difference is the key.
    assert {key for key in encoded if key not in plain} == {"fallback_from"}
    assert canonical_encode(
        cast(
            JsonValue,
            JsonObject(tuple(item for item in encoded.items() if item[0] != "fallback_from")),
        )
    ) == canonical_encode(cast(JsonValue, plain))


def _with_origin(origin: JsonValue) -> JsonObject:
    encoded = semantic_provenance_to_json(replace(_provenance(), fallback_from=_origin()))
    return JsonObject(
        (
            *tuple(item for item in encoded.items() if item[0] != "fallback_from"),
            ("fallback_from", origin),
        )
    )


def test_decoding_rejects_a_misshapen_origin_object() -> None:
    good = semantic_fallback_origin_to_json(_origin())
    assert _reason_of(lambda: semantic_provenance_from_json(_with_origin(None))) == (
        "semantic_provenance_json_shape_invalid"
    )
    with_unknown = JsonObject((*tuple(good.items()), ("url", "https://example.invalid")))
    assert _reason_of(lambda: semantic_provenance_from_json(_with_origin(with_unknown))) == (
        "semantic_provenance_json_shape_invalid"
    )
    missing = JsonObject(tuple(item for item in good.items() if item[0] != "reason"))
    assert _reason_of(lambda: semantic_provenance_from_json(_with_origin(missing))) == (
        "semantic_provenance_json_shape_invalid"
    )


def test_decoding_rejects_an_unclosed_reason_or_overflowing_count() -> None:
    good = semantic_fallback_origin_to_json(_origin())
    bad_reason = JsonObject(
        tuple((key, "not_a_reason" if key == "reason" else value) for key, value in good.items())
    )
    assert _reason_of(lambda: semantic_provenance_from_json(_with_origin(bad_reason))) == (
        "invalid_semantic_fallback_origin"
    )
    overflow = JsonObject(
        tuple((key, "9" if key == "attempted_count" else value) for key, value in good.items())
    )
    assert _reason_of(lambda: semantic_provenance_from_json(_with_origin(overflow))) == (
        "invalid_semantic_fallback_origin"
    )


def test_origin_encoder_refuses_anything_but_an_origin() -> None:
    assert (
        _reason_of(lambda: semantic_fallback_origin_to_json(cast(SemanticFallbackOrigin, object())))
        == "invalid_semantic_fallback_origin"
    )
    assert (
        _reason_of(
            lambda: semantic_fallback_origin_to_json(cast(SemanticFallbackOrigin, _provenance()))
        )
        == "invalid_semantic_fallback_origin"
    )
    assert type(_provenance()) is SemanticProvenance


def test_a_fallback_provenance_validates_against_the_frozen_1_1_0_schema() -> None:
    encoded = semantic_provenance_to_json(replace(_provenance(), fallback_from=_origin()))
    validate_schema_instance("semantic-provenance", "1.1.0", cast(JsonValue, encoded))
