from __future__ import annotations

import json
from pathlib import Path

from finishup.domain.privacy import NEVER_SEND_KINDS, EgressChannel, ForbiddenDataKind

_ROOT = Path(__file__).resolve().parents[3]


def test_never_send_fixture_and_domain_registry_are_identical() -> None:
    fixture = json.loads((_ROOT / "fixtures/privacy/PRIV-005-never-send.case.json").read_text())
    policy_kinds = fixture["input"]["policies"]["assisted"]["never_send"]
    assert set(policy_kinds) == {kind.value for kind in ForbiddenDataKind}
    assert NEVER_SEND_KINDS == frozenset(ForbiddenDataKind)


def test_every_unsupported_non_llm_fixture_branch_is_no_dispatch_channel_unavailable() -> None:
    fixture = json.loads(
        (_ROOT / "fixtures/privacy/PRIV-008-independent-channels.case.json").read_text()
    )
    expected = fixture["expected"]["unsupported_channels"]
    # update_checks ships a structural transport; the remaining three stay unavailable.
    channels = {
        channel.value
        for channel in EgressChannel
        if channel not in {EgressChannel.LLM_INFERENCE, EgressChannel.UPDATE_CHECKS}
    }
    assert set(expected) == channels
    for channel in channels:
        branch = expected[channel]
        assert branch == {
            **branch,
            "network_attempts": 0,
            "outcome": "channel_unavailable",
            "policy_transition_committed": False,
        }
        receipt = branch["decision_receipt"]
        assert receipt["safe_failure_reason"] == "channel_unavailable"
        assert "authorization_id" not in receipt
        assert "dispatch_id" not in receipt
        assert "request_commitment" not in receipt
        assert "request_body_bytes" not in receipt["counts"]
