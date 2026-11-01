"""Hook-boundary tests for service-owned routine classification."""

from __future__ import annotations

import pytest

from finishup.adapters.integrations.observation_local import self_observation_deliverable
from finishup.cli.observe_hooks import map_hook_payload_to_envelope
from finishup.domain.observation_selection import ObservationContentRole, classify_observation

_KEY = b"k" * 32
_SESSION = "hmac-sha256:" + "1" * 64


def test_structural_extraction_drops_forged_routine_action() -> None:
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        {
            "tool_name": "mystery_tool",
            "action": "routine_read",
            "tool_input": {"action": "routine_read"},
            "success": True,
        },
        session_commitment=_SESSION,
        event_ordinal=1,
        key_material=_KEY,
    )

    assert "action" not in envelope.structural_payload


def test_structural_extraction_emits_only_typed_routine_marker() -> None:
    payload = {
        "tool_name": "Read",
        "action": "routine_read",
        "tool_input": {"action": "routine_read"},
        "exit_status": 0,
    }
    classification = classify_observation(payload, "PostToolUse")
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        payload,
        session_commitment=_SESSION,
        event_ordinal=1,
        key_material=_KEY,
        classification=classification,
    )

    assert envelope.structural_payload["action"] == "routine_read"


@pytest.mark.parametrize(
    "command",
    [
        "finishup observe status",
        "finishup observe selection-status --workspace /exact/project",
        "finishup observe selection-preview --workspace /exact/project",
        "finishup closure-prepare --session-id session --writer-id writer",
    ],
)
def test_local_cli_self_reads_have_no_authenticated_launcher_reduction(command: str) -> None:
    """A shell command cannot prove which FinishUP launcher actually executed it."""

    payload = {
        "tool_name": "exec_command",
        "tool_input": {"cmd": command},
        "exit_status": 0,
    }
    classification = classify_observation(payload, "PostToolUse")
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        payload,
        session_commitment=_SESSION,
        event_ordinal=1,
        key_material=_KEY,
        classification=classification,
    )

    assert classification.routine_candidate is False
    assert classification.proven_routine_success is False
    assert classification.protected is True
    assert classification.content_role is ObservationContentRole.BOTH
    assert "unknown_operation" in classification.reason_tokens
    assert "action" not in envelope.structural_payload
    # ``exec_command`` is not an authenticated FinishUP MCP workflow spelling.
    assert self_observation_deliverable("PostToolUse", envelope.structural_payload) is True
