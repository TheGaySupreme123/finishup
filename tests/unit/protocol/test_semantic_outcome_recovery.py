"""Provider / AI-powered review recovery tokens (issue #742)."""

from __future__ import annotations

from yoetz.cli.render import render_human_check
from yoetz.domain.findings import SemanticFailureClass
from yoetz.mcp.summaries import summary_for_check
from yoetz.protocol.models import (
    CheckSuccessModel,
    CoverageModel,
    SemanticReason,
    SemanticStatus,
    SemanticWithheldItemModel,
)
from yoetz.protocol.recovery import (
    RECOVERY_DIRECTIVES,
    continuation_for_semantic_outcome,
    directive_for,
)

_FRONTIER = {"sequence": "3", "head_digest": "sha256:" + "a" * 64}
_CANARY = "sk-user-secret-should-never-appear"
_PROVIDER_CANARY = "I am the raw model output with field X malformed"


def test_adapter_failure_class_selects_credential_token() -> None:
    assert (
        continuation_for_semantic_outcome(
            status=SemanticStatus.UNAVAILABLE,
            reason=SemanticReason.TRANSPORT_UNAVAILABLE,
            failure_class=SemanticFailureClass.AUTHENTICATION,
        )
        == "semantic_credential_rejected"
    )
    assert (
        continuation_for_semantic_outcome(
            status=SemanticStatus.UNAVAILABLE,
            reason=SemanticReason.TRANSPORT_UNAVAILABLE,
            failure_class="authorization",
        )
        == "semantic_credential_rejected"
    )
    assert (
        continuation_for_semantic_outcome(
            status=SemanticStatus.UNAVAILABLE,
            reason=SemanticReason.TRANSPORT_UNAVAILABLE,
            failure_class=SemanticFailureClass.TRANSPORT,
        )
        == "semantic_transport_retry"
    )


def test_closed_reason_tokens_cover_issue_examples() -> None:
    assert (
        continuation_for_semantic_outcome(
            status=SemanticStatus.INVALID,
            reason=SemanticReason.RESPONSE_SCHEMA_INVALID,
        )
        == "semantic_response_invalid"
    )
    assert (
        continuation_for_semantic_outcome(
            status=SemanticStatus.INVALID,
            reason=SemanticReason.RESPONSE_CONTENT_INVALID,
        )
        == "semantic_response_truncated"
    )
    assert (
        continuation_for_semantic_outcome(
            status=SemanticStatus.FAILED,
            reason=SemanticReason.CASE_CAPACITY_EXCEEDED,
        )
        == "semantic_capacity_exceeded"
    )


def test_privacy_blocked_required_review_gets_safe_recovery() -> None:
    for status, reason in (
        (SemanticStatus.BLOCKED_FORBIDDEN_DATA, SemanticReason.NEVER_SEND_DETECTED),
        (SemanticStatus.CLASSIFICATION_UNCERTAIN, SemanticReason.CLASSIFICATION_UNCERTAIN),
    ):
        token = continuation_for_semantic_outcome(status=status, reason=reason)
        assert token == "semantic_privacy_blocked"
        directive = directive_for(token)
        assert directive is not None
        assert "NEW request_id" in directive.directive
        assert "resend" in directive.directive
        assert "local-only" in directive.directive


def test_terminal_outcome_reasons_are_not_misread_as_a_transport_diagnosis() -> None:
    """``retry_budget_exhausted`` and ``outcome_unknown`` name how a job ended, not why."""

    for reason in (SemanticReason.RETRY_BUDGET_EXHAUSTED, SemanticReason.OUTCOME_UNKNOWN):
        token = continuation_for_semantic_outcome(status=SemanticStatus.UNAVAILABLE, reason=reason)
        assert token == "semantic_no_judgment"
        directive = directive_for(token)
        assert directive is not None
        assert "transport" not in directive.directive.lower()


def test_predispatch_configuration_outcomes_carry_no_setup_prompt() -> None:
    """A check on an installation without a provider must not demand a credential every time."""

    for status, reason in (
        (SemanticStatus.NOT_CONFIGURED, SemanticReason.PROVIDER_NOT_CONFIGURED),
        (SemanticStatus.NOT_CONFIGURED, SemanticReason.LOCAL_MODEL_NOT_CONFIGURED),
        (SemanticStatus.UNAVAILABLE, SemanticReason.CREDENTIAL_UNAVAILABLE),
    ):
        assert continuation_for_semantic_outcome(status=status, reason=reason) is None


def test_directives_never_downgrade_required_review() -> None:
    """Every directive offering a local-only check also names the required-review rule."""

    for token, entry in RECOVERY_DIRECTIVES.items():
        if not token.startswith("semantic_") or "local-only" not in entry.directive:
            continue
        assert "For optional review" in entry.directive or "for optional review" in entry.directive
        assert "required review" in entry.directive
        assert "unmet" in entry.directive


def test_truncated_answer_directive_never_offers_a_second_job() -> None:
    directive = directive_for("semantic_response_truncated")
    assert directive is not None
    assert "NEW request_id" not in directive.directive
    assert "Do not spend a second job" in directive.directive


def test_succeeded_and_disabled_reasons_have_no_failure_directive() -> None:
    assert (
        continuation_for_semantic_outcome(
            status=SemanticStatus.SUCCEEDED,
            reason=SemanticReason.SEMANTIC_COMPLETED,
        )
        is None
    )
    assert (
        continuation_for_semantic_outcome(
            status=SemanticStatus.NOT_REQUESTED,
            reason=SemanticReason.DETERMINISTIC_MODE,
        )
        is None
    )
    assert (
        continuation_for_semantic_outcome(
            status=SemanticStatus.BLOCKED_BY_POLICY,
            reason=SemanticReason.CHANNEL_DISABLED,
        )
        is None
    )


def test_directives_never_copy_caller_or_provider_text() -> None:
    for token in (
        "semantic_response_invalid",
        "semantic_response_truncated",
        "semantic_credential_rejected",
        "semantic_capacity_exceeded",
        "semantic_timeout",
        "semantic_refused",
        "semantic_rate_limited",
        "semantic_transport_retry",
        "semantic_no_judgment",
        "semantic_coordinator_review",
        "semantic_privacy_blocked",
    ):
        entry = RECOVERY_DIRECTIVES[token]
        blob = f"{entry.directive} {entry.nudge or ''}"
        assert _CANARY not in blob
        assert _PROVIDER_CANARY not in blob
        assert "will fix" not in blob.lower()
        assert "guaranteed" not in blob.lower()


def test_check_renderers_project_registry_text_without_raw_output() -> None:
    envelope: dict[str, object] = {
        "ok": True,
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": "req_00000000-0000-4000-8000-000000000001",
        "session_id": "ses_00000000-0000-4000-8000-000000000001",
        "task_id": "tsk_00000000-0000-4000-8000-000000000001",
        "writer_id": "wri_00000000-0000-4000-8000-000000000001",
        "result_frontier": _FRONTIER,
        "subject_frontier": _FRONTIER,
        "verdict": "incomplete_check",
        "findings": [],
        "suppressed_count": "0",
        "semantic_status": "invalid",
        "semantic_reason": "response_content_invalid",
        "semantic_provenance": {
            "failure_class": "response_content",
            "status": "invalid",
            "reason": "response_content_invalid",
        },
        "coverage": {
            "publication_channels": ["engine_derived"],
            "authorship_assurance": "service_authenticated",
            "artifact_observation": "published_only",
            "evidence_immutability": "content_digest",
            "ledger_freshness": "current",
            "check_types": ["deterministic"],
            "known_gaps": ["semantic_relevance_review_not_run"],
        },
        "versions": {
            "protocol": "0.1",
            "engine": "test",
            "projection": "test",
            "policies": [],
        },
    }
    text = summary_for_check(envelope)
    assert "Continuation: semantic_response_truncated." in text
    assert _PROVIDER_CANARY not in text
    assert len(text.encode("ascii")) <= 512

    result = CheckSuccessModel.model_construct(
        verdict="incomplete_check",
        semantic_status="unavailable",
        semantic_reason="transport_unavailable",
        semantic_provenance=None,
        findings=(),
        suppressed_count="0",
        coverage=CoverageModel.model_construct(known_gaps=()),
        children=None,
        advisory_notes=(),
    )
    rendered = render_human_check(result)
    assert "Continuation: semantic_transport_retry" in rendered
    assert directive_for("semantic_transport_retry") is not None
    assert _CANARY not in rendered


def test_human_check_names_opaque_heuristic_withheld_items_without_content() -> None:
    result = CheckSuccessModel.model_construct(
        verdict="incomplete_check",
        semantic_status="succeeded",
        semantic_reason="completed",
        semantic_provenance=None,
        findings=(),
        suppressed_count="0",
        coverage=CoverageModel.model_construct(known_gaps=("content_redacted",)),
        children=None,
        advisory_notes=(),
        semantic_withheld_items=(
            SemanticWithheldItemModel(
                item_id="excerpt-heuristic",
                reason="never_send_heuristic",
            ),
        ),
    )
    rendered = render_human_check(result)
    assert "Withheld review items" in rendered
    assert "excerpt-heuristic: never_send_heuristic" in rendered
    assert "auth_token" not in rendered


def test_human_check_names_redacted_value_lines_and_the_fixed_agent_line() -> None:
    """PL2-1 (issue #982): refs and line numbers, the fixed agent line once, never a value."""

    from yoetz.domain.receipts import SEMANTIC_REDACTED_VALUES_AGENT_LINE
    from yoetz.protocol.models import SemanticRedactedValueModel

    result = CheckSuccessModel.model_construct(
        verdict="action_required",
        semantic_status="succeeded",
        semantic_reason="completed",
        semantic_provenance=None,
        findings=(),
        suppressed_count="0",
        coverage=CoverageModel.model_construct(known_gaps=("semantic_review_value_redacted",)),
        children=None,
        advisory_notes=(),
        semantic_redacted_values=(
            SemanticRedactedValueModel(
                item_id="excerpt-a",
                disposition="value_replaced",
                lines=(3, 7),
                source_ref="evd_10000000-0000-4000-8000-000000000021",
            ),
        ),
    )
    rendered = render_human_check(result)
    assert (
        "- evd_10000000-0000-4000-8000-000000000021 (item excerpt-a): value replaced, lines 3, 7 of the captured item"
    ) in rendered
    assert rendered.count(SEMANTIC_REDACTED_VALUES_AGENT_LINE) == 1
    plain = CheckSuccessModel.model_construct(
        verdict="no_issue_detected",
        semantic_status="succeeded",
        semantic_reason="completed",
        semantic_provenance=None,
        findings=(),
        suppressed_count="0",
        coverage=CoverageModel.model_construct(known_gaps=()),
        children=None,
        advisory_notes=(),
    )
    assert SEMANTIC_REDACTED_VALUES_AGENT_LINE not in render_human_check(plain)


def test_human_check_and_status_state_why_the_check_time_change_was_unavailable() -> None:
    from yoetz.cli.render import render_human_status
    from yoetz.protocol.models import StatusClosureReadinessModel, StatusSuccessModel

    gaps = ("check_time_change_unavailable", "check_time_change_unavailable_unsafe_root")
    result = CheckSuccessModel.model_construct(
        verdict="no_issue_detected",
        semantic_status="succeeded",
        semantic_reason="completed",
        semantic_provenance=None,
        findings=(),
        suppressed_count="0",
        coverage=CoverageModel.model_construct(known_gaps=gaps),
        children=None,
        advisory_notes=(),
    )
    rendered = render_human_check(result)
    assert "The check-time change was unavailable: the repository failed a safety check" in (
        rendered
    )
    assert (
        render_human_check(
            result.model_copy(
                update={"coverage": CoverageModel.model_construct(known_gaps=gaps[:1])}
            )
        ).count("The check-time change was unavailable")
        == 0
    )
    status = StatusSuccessModel.model_construct(
        head_frontier=type("Frontier", (), {"sequence": "7"})(),
        coverage=CoverageModel.model_construct(ledger_freshness="partial", known_gaps=gaps),
        # A real readiness model (issue #913 renders it); constructed without a checklist, as an
        # earlier build's result carries, so only the counts reach the text.
        closure_readiness=StatusClosureReadinessModel.model_construct(
            open_obligation_count="0",
            unanswered_finding_count="0",
            receipt_blocking_finding_count="0",
            state=None,
            agent_actionable=None,
            standing_limitations=None,
            acknowledged_not_done=None,
            acknowledged_not_done_count=None,
        ),
        page=None,
        gaps=(),
    )
    rendered_status = render_human_status(status)
    assert "Gaps: check_time_change_unavailable, check_time_change_unavailable_unsafe_root" in (
        rendered_status
    )
    assert "The check-time change was unavailable: the repository failed a safety check" in (
        rendered_status
    )


def test_receipt_and_status_render_redacted_values_from_wire_and_skip_malformed() -> None:
    from yoetz.cli.render import (
        _semantic_redacted_value_lines,  # pyright: ignore[reportPrivateUsage]
    )
    from yoetz.domain.receipts import SEMANTIC_REDACTED_VALUES_AGENT_LINE

    lines = _semantic_redacted_value_lines(
        (
            {"disposition": "item_withheld", "item_id": "excerpt-b", "lines": [2]},
            {"disposition": "value_replaced", "item_id": "x", "lines": [1], "value": "s3cr3t"},
        )
    )
    assert lines[1] == "- excerpt-b: item withheld, line 2 of the captured item"
    assert lines.count(SEMANTIC_REDACTED_VALUES_AGENT_LINE) == 1
    assert "s3cr3t" not in "\n".join(lines)
    assert _semantic_redacted_value_lines(()) == []
