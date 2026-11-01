"""The reviewed routine-read summary vector remains canonical and fail-closed."""

from __future__ import annotations

import json
from typing import Any, cast

import pytest

from finishup.adapters.integrations.observation_admission import build_routine_read_summary
from finishup.domain.observation import (
    ObservationEnvelope,
    observation_envelope_from_json,
    observation_envelope_to_json,
    routine_read_summary_from_envelope,
)
from finishup.domain.values import freeze_json
from finishup.protocol.canonical import canonical_digest, canonical_encode
from finishup.protocol.errors import ProtocolValueError
from fixture_loader import FixtureLoader

_FIXTURE = "observations/routine-read-summary.case.json"


def _document(fixture_loader: FixtureLoader) -> dict[str, Any]:
    return cast(dict[str, Any], fixture_loader.load_json(_FIXTURE))


def _envelopes(document: dict[str, Any]) -> tuple[ObservationEnvelope, ...]:
    input_block = cast(dict[str, Any], document["input"])
    raw = cast(list[Any], input_block["envelopes"])
    return tuple(observation_envelope_from_json(cast(Any, freeze_json(item))) for item in raw)


def test_summary_fixture_rebuilds_to_exact_canonical_identity_and_bytes(
    fixture_loader: FixtureLoader,
) -> None:
    document = _document(fixture_loader)
    input_block = cast(dict[str, Any], document["input"])
    expected = cast(dict[str, Any], document["expected"])

    summary = build_routine_read_summary(
        _envelopes(document),
        cast(str, input_block["fence"]),
    )
    wire = observation_envelope_to_json(summary)
    canonical = canonical_encode(wire)

    assert summary.source_identity == expected["summary_identity"]
    assert summary.structural_payload["member_digest"] == expected["member_digest"]
    assert canonical.hex() == expected["summary_canonical_hex"]
    assert canonical_digest(wire) == expected["summary_canonical_sha256"]
    assert routine_read_summary_from_envelope(summary).summary_identity == summary.source_identity


def test_summary_fixture_rejects_an_extra_member_field(
    fixture_loader: FixtureLoader,
) -> None:
    document = _document(fixture_loader)
    expected = cast(dict[str, Any], document["expected"])
    forged = cast(
        dict[str, Any],
        json.loads(canonical_encode(expected["summary_envelope"])),
    )
    structural = cast(dict[str, Any], forged["structural_payload"])
    members = cast(list[dict[str, Any]], structural["members"])
    members[0]["unexpected"] = "forged"

    with pytest.raises(ProtocolValueError):
        routine_read_summary_from_envelope(
            observation_envelope_from_json(cast(Any, freeze_json(forged)))
        )
