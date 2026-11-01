"""First-start recovery stays executable when a host exposes only MCP text (#744)."""

from __future__ import annotations

import json

import pytest
from mcp import types

from finishup.cli.render import render_human_error
from finishup.mcp.server import result_from_public_model
from finishup.mcp.summaries import MAX_SUMMARY_BYTES, summary_for_public_error
from finishup.protocol.errors import attach_reason_continuation
from finishup.protocol.models import StartResultModel
from finishup.protocol.start_recovery import start_recovery_guidance


@pytest.mark.parametrize(
    ("code", "reason", "instruction"),
    [
        ("BUNDLE_BUSY", "start_runtime_rebind_retry_ready", "Replay the exact"),
        ("BUNDLE_BUSY", "start_catalog_retry_ready", "Replay the exact"),
        ("BUNDLE_BUSY", "start_busy_retry_ready", "Replay the exact"),
        ("OPERATION_PENDING", "start_lease_pending", "Wait up to 60 seconds"),
    ],
)
def test_first_start_recovery_survives_all_text_surfaces(
    code: str, reason: str, instruction: str
) -> None:
    failure = StartResultModel.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "ok": False,
            "error": {
                "code": code,
                "message": "PRIVATE-MESSAGE-NOT-FOR-MCP-SUMMARY",
                "retryable": True,
                "correlation_id": "err_edd47974-68b1-4c5b-88e7-f063054f7760",
                "safe_details": dict(attach_reason_continuation({"reason_code": reason})),
            },
        }
    )
    assert failure.root.ok is False
    generic = result_from_public_model(failure)
    block = generic.content[0]
    assert isinstance(block, types.TextContent)
    assert instruction in block.text
    assert reason in block.text
    assert "PRIVATE-MESSAGE" not in block.text
    assert len(block.text.encode("ascii")) <= MAX_SUMMARY_BYTES
    assert instruction in render_human_error(failure.root.error)
    cursor = result_from_public_model(failure, host_profile="cursor")
    cursor_block = cursor.content[0]
    assert isinstance(cursor_block, types.TextContent)
    assert json.loads(cursor_block.text) == cursor.structuredContent
    assert json.loads(cursor_block.text)["error"]["safe_details"]["reason_code"] == reason


@pytest.mark.parametrize("reason", ["runtime_rebind_busy", "catalog_busy", "private/path", []])
def test_unclassified_busy_never_claims_a_released_start_lease(reason: object) -> None:
    details = {"reason_code": reason}
    assert start_recovery_guidance("BUNDLE_BUSY", True, details) == ""
    assert "Replay" not in summary_for_public_error(
        {"ok": False, "error": {"code": "BUNDLE_BUSY", "retryable": True, "safe_details": details}}
    )


def test_terminal_or_wrong_code_does_not_offer_retry() -> None:
    details = {"reason_code": "start_runtime_rebind_retry_ready"}
    assert start_recovery_guidance("BUNDLE_BUSY", False, details) == ""
    assert start_recovery_guidance("STORAGE_CORRUPT", True, details) == ""
