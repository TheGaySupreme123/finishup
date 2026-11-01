"""Property checks for bounded canonical ordinary-control frames."""

from __future__ import annotations

import struct

import pytest
from hypothesis import given
from hypothesis import strategies as st

from finishup.protocol.canonical import JsonValue
from finishup.protocol.schemas import load_schema_catalog
from finishup.service.control_protocol import (
    MAX_CONTROL_FRAME_BYTES,
    ControlProtocolError,
    decode_control_frame,
    encode_control_frame,
)


@given(
    client_kind=st.sampled_from(("cli", "mcp_bridge", "ui")),
    nonce=st.binary(min_size=32, max_size=32),
    patch=st.integers(min_value=0, max_value=9999),
)
def test_valid_hello_frames_round_trip_canonically(
    client_kind: str, nonce: bytes, patch: int
) -> None:
    value: dict[str, JsonValue] = {
        "protocol_version": "1.0",
        "client_kind": client_kind,
        "client_version": f"0.1.{patch}",
        "connection_nonce": nonce.hex(),
        "schema_manifest_digest": load_schema_catalog().manifest_digest,
    }
    encoded = encode_control_frame(value)
    decoded = decode_control_frame(encoded)

    assert decoded == value
    assert encode_control_frame(decoded) == encoded
    assert len(encoded) - 4 <= MAX_CONTROL_FRAME_BYTES


@given(declared=st.integers(min_value=MAX_CONTROL_FRAME_BYTES + 1, max_value=2**32 - 1))
def test_declared_oversize_rejects_without_payload(declared: int) -> None:
    with pytest.raises(ControlProtocolError) as caught:
        decode_control_frame(struct.pack(">I", declared))
    assert caught.value.reason == "frame_too_large"


@given(
    payload=st.binary(max_size=256),
    delta=st.integers(min_value=-3, max_value=3).filter(lambda value: value != 0),
)
def test_length_mismatch_never_accepts(payload: bytes, delta: int) -> None:
    declared = max(1, len(payload) + delta)
    with pytest.raises(ControlProtocolError):
        decode_control_frame(struct.pack(">I", declared) + payload)


@given(suffix=st.binary(min_size=1, max_size=32))
def test_complete_decoder_rejects_trailing_next_frame_bytes(suffix: bytes) -> None:
    value: dict[str, JsonValue] = {
        "protocol_version": "1.0",
        "client_kind": "cli",
        "client_version": "0.1.0",
        "connection_nonce": "0" * 64,
        "schema_manifest_digest": load_schema_catalog().manifest_digest,
    }
    encoded = encode_control_frame(value)
    with pytest.raises(ControlProtocolError) as caught:
        decode_control_frame(encoded + suffix)
    assert caught.value.reason == "frame_invalid"
