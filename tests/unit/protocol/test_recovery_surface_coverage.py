"""Producer-to-surface recovery: token travels, caller/provider text does not."""

from __future__ import annotations

from finishup.cli.hooks import (
    _LOCKED_CONTEXT,  # pyright: ignore[reportPrivateUsage]
    _RETRY_CONTEXT,  # pyright: ignore[reportPrivateUsage]
    _STORAGE_UNSAFE_CONTEXT,  # pyright: ignore[reportPrivateUsage]
)
from finishup.cli.observe_hooks import (
    _attachment_recovery_context,  # pyright: ignore[reportPrivateUsage]
)
from finishup.cli.render import (
    render_hook_recovery_suffix,
    render_local_recovery_lines,
    render_semantic_outcome_recovery_lines,
)
from finishup.domain.findings import SemanticFailureClass
from finishup.mcp.summaries import summary_for_check
from finishup.protocol.models import SemanticReason, SemanticStatus
from finishup.protocol.recovery import (
    continuation_for_reason,
    continuation_for_semantic_outcome,
    directive_for,
)

_CANARY = "sk-user-secret-should-never-appear"
_PROVIDER_CANARY = "I am the raw model output with field X malformed"


def test_timeout_kinds_keep_distinct_replay_rules() -> None:
    read = continuation_for_reason("request_timeout", operation_kind="read")
    write = continuation_for_reason("request_timeout", operation_kind="write")
    start = continuation_for_reason("request_timeout", operation_kind="start")
    assert read == "read_timeout_new_identity"
    assert write == "write_timeout_same_identity"
    assert start == "start_timeout_same_identity"
    assert {read, write, start} == {
        "read_timeout_new_identity",
        "write_timeout_same_identity",
        "start_timeout_same_identity",
    }
    assert "NEW request_id" in directive_for(read).directive  # type: ignore[union-attr]
    assert "exact request_id" in directive_for(write).directive  # type: ignore[union-attr]
    assert "same request_id" in directive_for(start).directive  # type: ignore[union-attr]
    assert "session" in directive_for(start).directive.lower()  # type: ignore[union-attr]


def test_hook_and_tui_surfaces_resolve_registry_tokens() -> None:
    assert "Continuation: vault_unlock_required." in _LOCKED_CONTEXT
    # The retry context covers busy, pending, draining, and projection reasons as well as
    # timeouts, and the service's retryable storage_unsafe code is not the CLI's local-state
    # repair: neither may borrow a single reason's token (issue #739).
    assert "Continuation:" not in _RETRY_CONTEXT
    assert "Continuation:" not in _STORAGE_UNSAFE_CONTEXT
    for context in (_LOCKED_CONTEXT, _RETRY_CONTEXT, _STORAGE_UNSAFE_CONTEXT):
        assert _CANARY not in context
        assert len(context.encode("ascii")) <= 512
    # The hook's own start identity is invisible to the agent, so a timed-out attachment carries
    # no read or start replay token; the agent's own start is the recovery.
    timeout_attach = _attachment_recovery_context("timeout")
    assert "Continuation:" not in timeout_attach
    assert "Call start" in timeout_attach
    assert "service_incompatible" in _attachment_recovery_context("service_incompatible")
    assert "Continuation:" not in _attachment_recovery_context("service_incompatible")
    assert render_hook_recovery_suffix("vault_locked") == " Continuation: vault_unlock_required."
    tui_lines = render_local_recovery_lines("vault_locked")
    assert tui_lines[0] == "Continuation: vault_unlock_required"
    assert any("unlock" in line.lower() for line in tui_lines)


def test_check_and_receipt_surfaces_share_semantic_token() -> None:
    token = continuation_for_semantic_outcome(
        status=SemanticStatus.UNAVAILABLE,
        reason=SemanticReason.TRANSPORT_UNAVAILABLE,
        failure_class=SemanticFailureClass.AUTHENTICATION,
    )
    assert token == "semantic_credential_rejected"
    summary = summary_for_check(
        {
            "verdict": "incomplete_check",
            "findings": [],
            "suppressed_count": "0",
            "semantic_status": "unavailable",
            "semantic_reason": "transport_unavailable",
            "semantic_provenance": {"failure_class": "authentication"},
            "result_frontier": {"sequence": "3", "head_digest": "sha256:" + "a" * 64},
        }
    )
    assert "Continuation: semantic_credential_rejected." in summary
    assert _PROVIDER_CANARY not in summary
    assert len(summary.encode("ascii")) <= 512
    lines = render_semantic_outcome_recovery_lines(
        status=SemanticStatus.UNAVAILABLE,
        reason=SemanticReason.TRANSPORT_UNAVAILABLE,
        provenance={"failure_class": "authentication"},
    )
    assert lines[0] == "Continuation: semantic_credential_rejected"
    blob = " ".join(lines)
    assert _CANARY not in blob
    assert _PROVIDER_CANARY not in blob
