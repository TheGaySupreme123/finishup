"""Project policy refusals retain their reason through the active control wire."""

from __future__ import annotations

from typing import Any, cast

import pytest

from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.schemas import validate_schema_instance
from finishup.service.control_protocol import decode_control_frame, encode_control_frame
from fixture_loader import FixtureLoader


def test_project_policy_denial_roundtrips_on_control_27(fixture_loader: FixtureLoader) -> None:
    fixture = cast(
        dict[str, Any], fixture_loader.load_json("canonical/control-project-policy-2.7.case.json")
    )
    frame = cast(dict[str, JsonValue], fixture["input"]["frame"])
    validate_schema_instance("control-result", "2.7.0", frame)
    assert canonical_encode(frame).hex() == fixture["expected"]["canonical_hex"]
    assert len(canonical_encode(frame)) == fixture["expected"]["canonical_byte_length"]
    assert canonical_digest(frame) == fixture["expected"]["canonical_sha256"]
    assert decode_control_frame(encode_control_frame(frame)) == frame
    with pytest.raises(ProtocolValueError):
        validate_schema_instance("control-result", "2.6.0", frame)
