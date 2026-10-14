"""A paused check names its continuation on the MCP text channel.

Codex reads ``structuredContent``, but hosts that read only ``content`` previously saw
"Operation outcome: recorded" for an ``awaiting_input`` or ``awaiting_human`` check, which has no
verdict and is waiting on one exact command plus a same-id replay.
"""

from __future__ import annotations

import uuid
from typing import Any, Final

import pytest
from mcp import types

from yoetz.mcp.server import result_from_public_model
from yoetz.mcp.summaries import summary_for_check_awaiting
from yoetz.protocol.models import CheckResultModel

_REQUEST: Final = f"req_{uuid.uuid4()}"
_PENDING: Final = f"ppr_{uuid.uuid4()}"
_INSTRUCTION: Final = "free text from the service that must not be copied"


def _body(state: str, continuation: dict[str, Any]) -> dict[str, Any]:
    reason = "review_input_required" if state == "awaiting_input" else "human_approval_required"
    frontier = {"sequence": "4", "head_digest": "sha256:" + "2" * 64}
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": _REQUEST,
        "ok": True,
        "state": state,
        "task_id": f"tsk_{uuid.uuid4()}",
        "session_id": f"ses_{uuid.uuid4()}",
        "writer_id": f"wri_{uuid.uuid4()}",
        "subject_frontier": frontier,
        "result_frontier": frontier,
        "semantic_status": state,
        "semantic_reason": reason,
        "continuation": continuation,
        "privacy_projection": {
            "sink": "agent_context",
            "local_disclosure_receipt_id": f"egr_{uuid.uuid4()}",
            "policy_id": f"pvy_{uuid.uuid4()}",
            "policy_version": "1",
            "policy_digest": "sha256:" + "0" * 64,
            "included_categories": [],
            "blocked_categories": [],
            "omitted_pointers": [],
            "projection_commitment": "hmac-sha256:" + "1" * 64,
        },
        "versions": {
            "protocol_version": "0.1",
            "engine_version": "0.1.0",
            "projection_version": "yoetz/0.1.0",
            "policy_packs": ["research-evidence/0.2.0", "work-integrity/0.3.0"],
        },
    }


_INPUT = _body(
    "awaiting_input",
    {
        "kind": "review_input_required",
        "command": ["yoetz", "publish-work", "--input", "PATH"],
        "replay_request_id": _REQUEST,
        "instruction": _INSTRUCTION,
    },
)
_HUMAN = _body(
    "awaiting_human",
    {
        "kind": "privacy_disclosure_decision",
        "pending_id": _PENDING,
        "expires_at": "2026-08-05T13:00:00.000Z",
        "command": ["yoetz", "privacy", "decide-disclosure", _PENDING],
        "replay_request_id": _REQUEST,
        "instruction": _INSTRUCTION,
    },
)


@pytest.mark.parametrize("host", ("generic", "claude", "codex"))
def test_awaiting_input_text_names_the_command_and_replay(host: str) -> None:
    result = result_from_public_model(
        CheckResultModel.model_validate(_INPUT),
        host_profile=host,  # pyright: ignore[reportArgumentType]
    )
    block = result.content[0]
    assert isinstance(block, types.TextContent)
    first = block.text.splitlines()[0]
    assert first.startswith("Check state: awaiting_input (review_input_required); no verdict yet.")
    assert "yoetz publish-work --input PATH" in first
    assert f"replay the same check with request_id {_REQUEST}" in first
    assert _INSTRUCTION not in block.text


def test_awaiting_human_text_names_the_pending_decision() -> None:
    text = summary_for_check_awaiting(CheckResultModel.model_validate(_HUMAN).model_dump())
    assert f"yoetz privacy decide-disclosure {_PENDING}" in text
    assert "Expires at 2026-08-05T13:00:00.000Z." in text
    assert _REQUEST in text


def test_an_unrecognized_command_is_never_echoed() -> None:
    hostile = dict(_INPUT)
    hostile["continuation"] = {
        **_INPUT["continuation"],
        "command": ["yoetz", "publish-work", "--input", "/etc/passwd; rm -rf ~"],
    }
    text = summary_for_check_awaiting(hostile)
    assert "passwd" not in text
    assert "structuredContent.continuation" in text


def test_a_concluded_check_gets_no_awaiting_line() -> None:
    assert summary_for_check_awaiting({"ok": True, "verdict": "no_issue_detected"}) == ""
