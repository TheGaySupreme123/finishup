"""Optional routine detail obeys the budget shown in the owner preview."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import pytest

from finishup.cli.observe_hooks import _visible_content_chunks, map_hook_payload_to_envelope
from finishup.domain.observation_budget import ObservationMode, mode_limits


@pytest.mark.parametrize(
    "mode,expected", [(ObservationMode.FOCUSED, 16_384), (ObservationMode.DETAILED, 65_536)]
)
def test_optional_output_obeys_mode_budget(mode: ObservationMode, expected: int) -> None:
    payload = {"tool_name": "Read", "tool_use_id": "public-read", "tool_output": "x" * 100_000}
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        payload,
        session_commitment="hmac-sha256:" + "a" * 64,
        event_ordinal=1,
        key_material=b"synthetic-observation-test-key-01",
    )
    chunks, truncated = _visible_content_chunks(
        "PostToolUse",
        payload,
        envelope=envelope,
        workspace_locator=None,
        optional_limits=mode_limits(mode),
    )
    assert sum(len(chunk.content) for chunk in chunks) == expected
    assert truncated
    # Protected evidence retains the pre-existing content cap independently
    # of the smaller optional detail selected by the owner.
    protected, protected_truncated = _visible_content_chunks(
        "PostToolUse",
        payload,
        envelope=envelope,
        workspace_locator=None,
    )
    assert sum(len(chunk.content) for chunk in protected) == 100_000
    assert not protected_truncated
