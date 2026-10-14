"""Unit tests for local observation-advice policies."""

from __future__ import annotations

from dataclasses import replace

import pytest

from yoetz.domain.findings import FindingKind
from yoetz.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationLifecycle,
    ObservationSource,
)
from yoetz.domain.values import JsonObject, Timestamp
from yoetz.kernel.policies.observation_advice import (
    SEMANTIC_ATTENTION_TOKENS,
    STANDING_MACHINE_ACTIONS,
    ObservationAdviceCandidate,
    ObservationAdviceContext,
    ObservationCheckFact,
    ObservationCompositionFact,
    ObservationInspectFact,
    observation_advice_findings,
)

_COMMITMENT = "hmac-sha256:" + "a" * 64
_DIGEST = "sha256:" + "b" * 64
_TIME = Timestamp("2026-07-22T21:00:00.000Z")


def _cursor(event_pos: int = 1) -> ObservationCursor:
    return ObservationCursor(
        source_generation=1,
        byte_position=event_pos * 10,
        event_position=event_pos,
        last_source_commitment=_COMMITMENT,
        mapping_version="codex-obs-hook/1.0.0",
    )


def _envelope(
    event_kind: str,
    *,
    pos: int,
    identity: str,
    payload: dict[str, object],
    gaps: tuple[str, ...] = (),
) -> ObservationEnvelope:
    return ObservationEnvelope(
        session_commitment=_COMMITMENT,
        event_kind=event_kind,
        source_identity=identity,
        source=ObservationSource.CODEX_HOOK,
        cursor=_cursor(pos),
        receipt_time=_TIME,
        structural_payload=JsonObject(payload),
        content_object_refs=(),
        gap_codes=gaps,
    )


def _rules(context: ObservationAdviceContext) -> set[str]:
    return {item.rule_code for item in observation_advice_findings(context)}


def test_failed_command_left_unresolved() -> None:
    envelopes = (
        _envelope(
            "PostToolUse",
            pos=1,
            identity="hook:fail1",
            payload={"tool_name": "shell", "exit_status": 1, "correlation_id": "c1"},
        ),
    )
    rules = _rules(
        ObservationAdviceContext(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
        )
    )
    assert "failed_command_unresolved" in rules


def test_failed_command_cleared_by_retry() -> None:
    envelopes = (
        _envelope(
            "PostToolUse",
            pos=1,
            identity="hook:fail1",
            payload={"tool_name": "shell", "exit_status": 1, "correlation_id": "c1"},
        ),
        _envelope(
            "PostToolUse",
            pos=2,
            identity="hook:ok1",
            payload={"tool_name": "shell", "exit_status": 0, "correlation_id": "c1"},
        ),
    )
    rules = _rules(
        ObservationAdviceContext(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
        )
    )
    assert "failed_command_unresolved" not in rules


def test_failed_stream_output_uses_originating_tool_name() -> None:
    envelopes = (
        _envelope(
            "response_item",
            pos=1,
            identity="stream:call",
            payload={"action": "function_call", "tool_name": "shell", "tool_call_id": "call-1"},
        ),
        _envelope(
            "response_item",
            pos=2,
            identity="stream:output",
            payload={
                "action": "function_call_output",
                "tool_call_id": "call-1",
                "exit_status": 1,
                "result_status": "completed",
            },
        ),
    )
    rules = _rules(
        ObservationAdviceContext(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
        )
    )
    assert "failed_command_unresolved" in rules


def test_conflicting_stream_output_uses_originating_tool_name() -> None:
    envelopes = (
        _envelope(
            "response_item",
            pos=1,
            identity="stream:call-conflict",
            payload={"action": "function_call", "tool_name": "shell", "tool_call_id": "call-2"},
        ),
        _envelope(
            "response_item",
            pos=2,
            identity="stream:output-conflict",
            payload={
                "action": "function_call_output",
                "tool_call_id": "call-2",
                "tool_name": "publish_work",
                "exit_status": 1,
                "result_status": "completed",
            },
        ),
    )
    rules = _rules(
        ObservationAdviceContext(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
        )
    )
    assert "failed_command_unresolved" in rules


def test_completion_uses_originating_tool_for_successful_stream_output() -> None:
    """The output row inherits the originating call's verification tool."""

    envelopes = (
        _envelope(
            "response_item",
            pos=1,
            identity="stream:call-success",
            payload={"action": "function_call", "tool_name": "pytest", "tool_call_id": "call-3"},
        ),
        _envelope(
            "response_item",
            pos=2,
            identity="stream:output-success",
            payload={
                "action": "function_call_output",
                "tool_call_id": "call-3",
                "exit_status": 0,
                "result_status": "completed",
            },
        ),
        _envelope(
            "PostToolUse",
            pos=3,
            identity="hook:completion-after-success",
            payload={"claim_kind": "completion"},
        ),
    )
    rules = _rules(
        ObservationAdviceContext(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
        )
    )
    assert "completion_without_verification" not in rules


def test_stream_pairing_does_not_cross_session_boundary() -> None:
    origin = _envelope(
        "response_item",
        pos=1,
        identity="stream:call-session-boundary",
        payload={"action": "function_call", "tool_name": "shell", "tool_call_id": "call-4"},
    )
    output = _envelope(
        "response_item",
        pos=2,
        identity="stream:output-session-boundary",
        payload={
            "action": "function_call_output",
            "tool_call_id": "call-4",
            "exit_status": 1,
        },
    )
    output = replace(output, session_commitment="hmac-sha256:" + "b" * 64)
    rules = _rules(
        ObservationAdviceContext(
            envelopes=(origin, output),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
        )
    )
    assert "failed_command_unresolved" not in rules


def test_stream_pairing_does_not_cross_source_boundary() -> None:
    origin = _envelope(
        "response_item",
        pos=1,
        identity="stream:call-source-boundary",
        payload={"action": "function_call", "tool_name": "shell", "tool_call_id": "call-5"},
    )
    output = _envelope(
        "response_item",
        pos=2,
        identity="stream:output-source-boundary",
        payload={
            "action": "function_call_output",
            "tool_call_id": "call-5",
            "exit_status": 1,
        },
    )
    output = replace(output, source=ObservationSource.CODEX_SESSION_STREAM)
    rules = _rules(
        ObservationAdviceContext(
            envelopes=(origin, output),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
        )
    )
    assert "failed_command_unresolved" not in rules


def test_edit_after_successful_check() -> None:
    envelopes = (
        _envelope(
            "PostToolUse",
            pos=1,
            identity="hook:check",
            payload={"tool_name": "pytest", "exit_status": 0},
        ),
        _envelope(
            "PostToolUse",
            pos=2,
            identity="hook:edit",
            payload={
                "tool_name": "apply_patch",
                "action": "write",
                "changed_paths_digest": _DIGEST,
            },
        ),
    )
    findings = observation_advice_findings(
        ObservationAdviceContext(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
        )
    )
    assert any(item.rule_code == "edit_after_successful_check" for item in findings)
    assert any(item.kind is FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE for item in findings)


def _passed_check(*, at: int = 1) -> ObservationCheckFact:
    """One current passed approved-check fact: the typed verification baseline."""

    return ObservationCheckFact(
        approval_commitment=_DIGEST,
        subject_state_digest=_DIGEST,
        status="passed",
        cursor_event_position=at,
    )


def _stale_candidates(
    envelopes: tuple[ObservationEnvelope, ...],
    checks: tuple[ObservationCheckFact, ...] = (),
) -> tuple[ObservationAdviceCandidate, ...]:
    return tuple(
        item
        for item in observation_advice_findings(
            ObservationAdviceContext(
                envelopes=envelopes,
                lifecycle=ObservationLifecycle.ACTIVE,
                gaps=(),
                check_facts=checks,
            )
        )
        if item.rule_code == "edit_after_successful_check"
    )


def _paired_edit(
    *,
    call_id: str,
    pre_pos: int,
    post_pos: int,
    prefix: str = "hook",
) -> tuple[ObservationEnvelope, ObservationEnvelope]:
    """One logical host edit observed as a PreToolUse/PostToolUse pair."""

    return (
        _envelope(
            "PreToolUse",
            pos=pre_pos,
            identity=f"{prefix}:{call_id}-pre",
            payload={
                "tool_name": "Write",
                "tool_call_id": call_id,
                "action": "claude_tool_pending",
                "changed_paths_digest": _DIGEST,
            },
        ),
        _envelope(
            "PostToolUse",
            pos=post_pos,
            identity=f"{prefix}:{call_id}-post",
            payload={
                "tool_name": "Write",
                "tool_call_id": call_id,
                "action": "claude_tool_success",
                "success": True,
                "changed_paths_digest": _DIGEST,
            },
        ),
    )


def test_paired_edit_phases_yield_one_stale_candidate() -> None:
    """Issue #680: pre/post phases of one host edit are one condition."""

    candidates = _stale_candidates(
        _paired_edit(call_id="call-1", pre_pos=2, post_pos=3), (_passed_check(),)
    )
    assert len(candidates) == 1
    # Both mapped phases prove the one condition without identifying it.
    assert candidates[0].evidence_refs == ("hook:call-1-post", "hook:call-1-pre")


def test_stale_candidate_identity_survives_a_growing_evidence_window() -> None:
    pre, post = _paired_edit(call_id="call-1", pre_pos=2, post_pos=3)
    pre_only = _stale_candidates((pre,), (_passed_check(),))
    paired = _stale_candidates((pre, post), (_passed_check(),))
    assert len(pre_only) == 1
    assert len(paired) == 1
    assert pre_only[0].detail_token == paired[0].detail_token


def test_distinct_tool_calls_remain_distinct_stale_candidates() -> None:
    candidates = _stale_candidates(
        (
            *_paired_edit(call_id="call-1", pre_pos=2, post_pos=3),
            *_paired_edit(call_id="call-2", pre_pos=4, post_pos=5),
        ),
        (_passed_check(),),
    )
    assert len({item.detail_token for item in candidates}) == 2


def test_reused_call_id_across_generations_does_not_coalesce() -> None:
    first_pre, first_post = _paired_edit(call_id="call-1", pre_pos=2, post_pos=3)
    later_pre, later_post = _paired_edit(call_id="call-1", pre_pos=4, post_pos=5, prefix="gen2")
    later_pre = replace(later_pre, cursor=replace(later_pre.cursor, source_generation=2))
    later_post = replace(later_post, cursor=replace(later_post.cursor, source_generation=2))
    candidates = _stale_candidates(
        (first_pre, first_post, later_pre, later_post), (_passed_check(),)
    )
    assert len({item.detail_token for item in candidates}) == 2


def test_post_only_profile_emits_one_candidate_for_its_one_phase() -> None:
    """Cursor's current post-only profile needs no fabricated pre-event."""

    edit = _envelope(
        "PostToolUse",
        pos=2,
        identity="cursor:edit",
        payload={
            "tool_name": "Write",
            "action": "claude_tool_success",
            "success": True,
            "changed_paths_digest": _DIGEST,
        },
    )
    candidates = _stale_candidates((edit,), (_passed_check(),))
    assert len(candidates) == 1
    assert candidates[0].evidence_refs == ("cursor:edit",)


def _shell(*, pos: int, identity: str, routine: bool, tool: str = "Bash") -> ObservationEnvelope:
    payload: dict[str, object] = {
        "tool_name": tool,
        "success": True,
        "correlation_id": identity,
    }
    if routine:
        payload["action"] = "routine_read"
    return _envelope("PostToolUse", pos=pos, identity=identity, payload=payload)


def _edit(*, pos: int, identity: str) -> ObservationEnvelope:
    return _envelope(
        "PostToolUse",
        pos=pos,
        identity=identity,
        payload={
            "tool_name": "Write",
            "action": "claude_tool_success",
            "success": True,
            "changed_paths_digest": _DIGEST,
            "correlation_id": identity,
        },
    )


def test_routine_read_does_not_establish_a_verification_baseline() -> None:
    """Issue #681: a successful routine read is not a check."""

    envelopes = (
        _shell(pos=1, identity="read-1", routine=True),
        _edit(pos=2, identity="write-1"),
    )
    assert _stale_candidates(envelopes) == ()


def test_successful_shell_command_does_not_establish_a_verification_baseline() -> None:
    """A generic host shell returning zero proves an exit code, not a check."""

    envelopes = (
        _shell(pos=1, identity="cmd-1", routine=False),
        _edit(pos=2, identity="write-1"),
    )
    assert _stale_candidates(envelopes) == ()


def test_detailed_mode_routine_read_without_the_marker_is_still_not_a_check() -> None:
    """Detailed mode keeps ``function_call_output``; the tool identity still governs."""

    envelopes = (
        _envelope(
            "PostToolUse",
            pos=1,
            identity="stream:read-1",
            payload={
                "action": "function_call_output",
                "tool_name": "shell",
                "tool_call_id": "call-1",
                "exit_status": 0,
            },
        ),
        _edit(pos=2, identity="write-1"),
    )
    assert _stale_candidates(envelopes) == ()


def test_verification_tool_success_still_establishes_a_baseline() -> None:
    envelopes = (
        _shell(pos=1, identity="check-1", routine=False, tool="pytest"),
        _edit(pos=2, identity="write-1"),
    )
    assert len(_stale_candidates(envelopes)) == 1


def test_routine_read_does_not_move_a_check_fact_baseline() -> None:
    """A later routine read neither clears nor carries the baseline past an edit."""

    envelopes = (
        _edit(pos=2, identity="write-1"),
        _shell(pos=3, identity="read-1", routine=True),
    )
    assert len(_stale_candidates(envelopes, (_passed_check(),))) == 1


def test_only_a_current_passed_check_fact_establishes_a_baseline() -> None:
    edit = _edit(pos=5, identity="write-1")
    for status in ("passed_not_current", "failed", "stale", "unknown"):
        assert (
            _stale_candidates(
                (edit,),
                (
                    ObservationCheckFact(
                        approval_commitment=_DIGEST,
                        subject_state_digest=_DIGEST,
                        status=status,
                        cursor_event_position=1,
                    ),
                ),
            )
            == ()
        )
    assert (
        _stale_candidates(
            (edit,),
            (
                ObservationCheckFact(
                    approval_commitment=_DIGEST,
                    subject_state_digest=_DIGEST,
                    status="passed",
                    cursor_event_position=1,
                    is_current=False,
                ),
            ),
        )
        == ()
    )
    assert len(_stale_candidates((edit,), (_passed_check(),))) == 1


def test_completion_after_only_a_routine_read_remains_unverified() -> None:
    """Issue #681: a routine read cannot support a completion claim."""

    envelopes = (
        _shell(pos=1, identity="read-1", routine=True),
        _envelope(
            "PostToolUse", pos=2, identity="hook:claim", payload={"claim_kind": "completion"}
        ),
    )
    assert "completion_without_verification" in _rules(
        ObservationAdviceContext(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
        )
    )


def test_completion_after_only_a_successful_shell_command_remains_unverified() -> None:
    envelopes = (
        _shell(pos=1, identity="cmd-1", routine=False),
        _envelope(
            "PostToolUse", pos=2, identity="hook:claim", payload={"claim_kind": "completion"}
        ),
    )
    assert "completion_without_verification" in _rules(
        ObservationAdviceContext(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
        )
    )


def test_failed_shell_command_advice_is_unchanged_by_check_qualification() -> None:
    """#681 narrows what proves a check, not which commands report outcomes."""

    rules = _rules(
        ObservationAdviceContext(
            envelopes=(
                _envelope(
                    "PostToolUse",
                    pos=1,
                    identity="hook:fail-bash",
                    payload={"tool_name": "bash", "exit_status": 1, "correlation_id": "c9"},
                ),
            ),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
        )
    )
    assert "failed_command_unresolved" in rules


def test_completion_without_verification() -> None:
    envelopes = (
        _envelope(
            "PostToolUse",
            pos=1,
            identity="hook:claim",
            payload={"tool_name": "publish_work", "claim_kind": "completion"},
        ),
    )
    rules = _rules(
        ObservationAdviceContext(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            check_facts=(),
        )
    )
    assert "completion_without_verification" in rules


def test_completed_tool_result_is_not_an_authored_completion_claim() -> None:
    """Host/tool completion status cannot stand in for the agent's claim."""

    rules = _rules(
        ObservationAdviceContext(
            envelopes=(
                _envelope(
                    "PostToolUse",
                    pos=1,
                    identity="hook:tool-completed",
                    payload={
                        "tool_name": "publish_work",
                        "result_status": "completed",
                    },
                ),
            ),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            check_facts=(),
        )
    )
    assert "completion_without_verification" not in rules


def test_static_test_for_live_claim() -> None:
    envelopes = (
        _envelope(
            "PostToolUse",
            pos=1,
            identity="hook:liveclaim",
            payload={"tool_name": "publish_work", "claim_kind": "live_wire_ok"},
        ),
        _envelope(
            "PostToolUse",
            pos=2,
            identity="hook:pytest",
            payload={"tool_name": "pytest", "exit_status": 0, "mapping_hint": "static"},
        ),
    )
    rules = _rules(
        ObservationAdviceContext(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
        )
    )
    assert "static_test_for_live_claim" in rules


def test_subagent_finding_unaddressed() -> None:
    envelopes = (
        _envelope(
            "SubagentStop",
            pos=1,
            identity="hook:sub",
            payload={"subagent_id": "sub-1", "result_status": "finding", "success": False},
        ),
    )
    rules = _rules(
        ObservationAdviceContext(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
        )
    )
    assert "subagent_finding_unaddressed" in rules


def test_change_outside_plan() -> None:
    plan = ("sha256:" + "c" * 64,)
    envelopes = (
        _envelope(
            "PostToolUse",
            pos=1,
            identity="hook:chg",
            payload={"tool_name": "apply_patch", "changed_paths_digest": _DIGEST},
        ),
    )
    rules = _rules(
        ObservationAdviceContext(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            plan_path_digests=plan,
            inspect_fact=ObservationInspectFact(
                selection_digest=_DIGEST,
                relative_paths=("src/a.py",),
                changed_paths_digest=_DIGEST,
            ),
        )
    )
    assert "change_outside_plan" in rules


def test_observation_gap_or_stale() -> None:
    rules = _rules(
        ObservationAdviceContext(
            envelopes=(),
            lifecycle=ObservationLifecycle.DEGRADED,
            gaps=(ObservationGapCode.SOURCE_LAG.value,),
        )
    )
    assert "observation_gap_or_stale" in rules


def test_standing_unpaired_record_raises_no_stale_advisory() -> None:
    """#917: only conditions that can recover in session raise ``refresh_observation``."""

    standing_context = ObservationAdviceContext(
        envelopes=(),
        lifecycle=ObservationLifecycle.ACTIVE,
        gaps=(ObservationGapCode.UNPAIRED_EVENT.value,),
    )
    assert "observation_gap_or_stale" not in _rules(standing_context)
    for transient in (
        ObservationGapCode.SOURCE_LAG,
        ObservationGapCode.CURSOR_STALE,
        ObservationGapCode.SERVICE_UNAVAILABLE,
        ObservationGapCode.VAULT_LOCKED,
    ):
        candidates = observation_advice_findings(
            replace(
                standing_context,
                gaps=(ObservationGapCode.UNPAIRED_EVENT.value, transient.value),
            )
        )
        gap = [item for item in candidates if item.rule_code == "observation_gap_or_stale"]
        assert len(gap) == 1, transient
        # The live cause leads the refs; the standing record is never named as one.
        assert gap[0].evidence_refs[0] == f"cause:{transient.value}"
        assert "cause:unpaired_event" not in gap[0].evidence_refs
    for standing_gap in (
        ObservationGapCode.UNSUPPORTED_EVENT,
        ObservationGapCode.UNSUPPORTED_FORMAT,
    ):
        assert "observation_gap_or_stale" not in _rules(
            replace(standing_context, gaps=(standing_gap.value,))
        )
    # A lifecycle label without a named recoverable cause is operator status, not
    # agent-facing work. In particular, a drain backlog must not inject ceremony.
    stale = observation_advice_findings(
        replace(standing_context, lifecycle=ObservationLifecycle.STALE)
    )
    assert "observation_gap_or_stale" not in {item.rule_code for item in stale}


def test_provider_not_ready() -> None:
    rules = _rules(
        ObservationAdviceContext(
            envelopes=(),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            composition=ObservationCompositionFact(
                semantic_configured=True,
                semantic_ready=False,
                provider_factory_ids=("openai",),
                connected_provider_ids=(),
            ),
        )
    )
    assert "provider_not_ready" in rules


def test_registry_lag_alone_does_not_emit_provider_not_ready() -> None:
    """A structurally usable provider absent from the lazy registry is not "not ready" (#265).

    Registry activation is repository-scoped and re-established automatically at
    dispatch, so a configured provider missing from the connected set proves
    nothing the operator can act on with connect_provider.
    """

    rules = _rules(
        ObservationAdviceContext(
            envelopes=(),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            composition=ObservationCompositionFact(
                semantic_configured=True,
                semantic_ready=True,
                provider_factory_ids=("fireworks",),
                connected_provider_ids=(),
            ),
        )
    )
    assert "provider_not_ready" not in rules


def test_provider_not_ready_requires_semantic_to_be_configured() -> None:
    """With AI-powered review disabled, connect_provider advice has no action to recommend (#265)."""

    rules = _rules(
        ObservationAdviceContext(
            envelopes=(),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            composition=ObservationCompositionFact(
                semantic_configured=False,
                semantic_ready=False,
                provider_factory_ids=("fireworks",),
                connected_provider_ids=(),
            ),
        )
    )
    assert "provider_not_ready" not in rules


def test_provider_not_ready_names_the_unusable_configured_provider() -> None:
    """The structural condition keeps naming the configured provider as evidence."""

    context = ObservationAdviceContext(
        envelopes=(),
        lifecycle=ObservationLifecycle.ACTIVE,
        gaps=(),
        composition=ObservationCompositionFact(
            semantic_configured=True,
            semantic_ready=False,
            provider_factory_ids=("fireworks",),
            connected_provider_ids=(),
        ),
    )
    candidates = observation_advice_findings(context)
    item = next(item for item in candidates if item.rule_code == "provider_not_ready")
    assert item.evidence_refs == ("fireworks",)
    assert item.next_action == "connect_provider"


def _intent_context(
    *, intended: bool, ready: bool = False, token: str | None = None
) -> ObservationAdviceContext:
    return ObservationAdviceContext(
        envelopes=(),
        lifecycle=ObservationLifecycle.ACTIVE,
        gaps=(),
        composition=ObservationCompositionFact(
            semantic_configured=intended,
            semantic_ready=ready,
            provider_factory_ids=(),
            connected_provider_ids=(),
            semantic_attention=token,
            semantic_attention_provider=None if token is None else "openai-codex",
        ),
    )


@pytest.mark.parametrize("token", [None, *sorted(SEMANTIC_ATTENTION_TOKENS)])
@pytest.mark.parametrize("ready", [False, True])
def test_private_or_unbound_install_gets_no_provider_repair_advice(
    ready: bool, token: str | None
) -> None:
    """No external review intended means nothing to connect, sign in to, or repair (#844).

    Attention memory can outlive a switch to private until recomposition, so a stale
    sign-in or repair token must not surface once intent is gone.
    """

    candidates = observation_advice_findings(
        _intent_context(intended=False, ready=ready, token=token)
    )
    assert not {item.next_action for item in candidates} & STANDING_MACHINE_ACTIONS


def test_intended_provider_without_a_factory_still_names_not_ready() -> None:
    """A bound, egress-permitted endpoint that cannot build stays actionable (#844)."""

    candidates = observation_advice_findings(_intent_context(intended=True))
    item = next(item for item in candidates if item.rule_code == "provider_not_ready")
    assert item.next_action == "connect_provider"
    assert item.evidence_refs == ("semantic:not_ready",)


def _attention_context(
    token: str | None, *, configured: bool = True, ready: bool = True
) -> ObservationAdviceContext:
    return ObservationAdviceContext(
        envelopes=(),
        lifecycle=ObservationLifecycle.ACTIVE,
        gaps=(),
        composition=ObservationCompositionFact(
            semantic_configured=configured,
            semantic_ready=ready,
            provider_factory_ids=("openai-codex",),
            connected_provider_ids=("openai-codex",),
            semantic_attention=token,
            semantic_attention_provider=None if token is None else "openai-codex",
        ),
    )


def test_codex_sign_in_failure_is_standing_sign_in_advice() -> None:
    """A structurally ready Codex path whose last attempt found no login (#819)."""

    candidates = observation_advice_findings(_attention_context("sign_in_required"))
    item = next(item for item in candidates if item.rule_code == "semantic_sign_in_required")
    assert item.next_action == "renew_provider_sign_in"
    assert item.next_action in STANDING_MACHINE_ACTIONS
    assert item.kind is FindingKind.MATERIAL_LIMITATION_OMITTED
    assert item.evidence_refs == ("openai-codex", "semantic:sign_in_required")
    assert "provider_not_ready" not in {entry.rule_code for entry in candidates}


@pytest.mark.parametrize(
    ("token", "next_action"),
    (
        ("credential_rejected", "repair_semantic_provider"),
        ("access_denied", "repair_semantic_provider"),
        ("quota_exhausted", "repair_semantic_provider"),
        ("model_unavailable", "repair_semantic_provider"),
        ("runtime_update_required", "update_yoetz"),
    ),
)
def test_other_repairable_causes_are_standing_provider_attention(
    token: str, next_action: str
) -> None:
    candidates = observation_advice_findings(_attention_context(token))
    item = next(item for item in candidates if item.rule_code == "semantic_provider_attention")
    assert item.next_action == next_action
    assert next_action in STANDING_MACHINE_ACTIONS
    assert item.detail_token == f"semantic-attention:{token}"


def test_every_attention_token_maps_to_a_rule() -> None:
    for token in SEMANTIC_ATTENTION_TOKENS:
        assert observation_advice_findings(_attention_context(token))


def test_attention_needs_a_configured_structurally_ready_path() -> None:
    """Disabled review has nothing to repair; an unusable path is provider_not_ready's."""

    assert not observation_advice_findings(_attention_context(None))
    assert not observation_advice_findings(_attention_context("quota_exhausted", configured=False))
    rules = _rules(_attention_context("sign_in_required", ready=False))
    assert rules == {"provider_not_ready"}


def test_unknown_attention_token_is_rejected() -> None:
    with pytest.raises(ValueError, match="observation_advice_invalid"):
        ObservationCompositionFact(
            semantic_configured=True,
            semantic_ready=True,
            provider_factory_ids=(),
            connected_provider_ids=(),
            semantic_attention="please sign in at evil.example",
        )


def test_semantic_claim_without_attempt() -> None:
    envelopes = (
        _envelope(
            "PostToolUse",
            pos=1,
            identity="hook:sem",
            payload={"tool_name": "publish_work", "claim_kind": "semantic_review_pass"},
        ),
    )
    rules = _rules(
        ObservationAdviceContext(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
        )
    )
    assert "semantic_claim_without_attempt" in rules


def test_check_fact_binds_edit_staleness() -> None:
    envelopes = (
        _envelope(
            "PostToolUse",
            pos=5,
            identity="hook:edit",
            payload={"tool_name": "apply_patch", "action": "write"},
        ),
    )
    rules = _rules(
        ObservationAdviceContext(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            check_facts=(
                ObservationCheckFact(
                    approval_commitment=_DIGEST,
                    subject_state_digest=_DIGEST,
                    status="passed",
                    cursor_event_position=2,
                ),
            ),
        )
    )
    assert "edit_after_successful_check" in rules


# --- #909: the advice reads the shared supersession rule -----------------------------------------

_PYTEST_X = "hmac-sha256:" + "1" * 64
_PYTEST_Y = "hmac-sha256:" + "2" * 64


def _bash(
    pos: int,
    call: str,
    *,
    success: bool,
    commitment: str | None,
    event_kind: str = "PostToolUse",
) -> ObservationEnvelope:
    """A Claude Code ordinary-profile Bash result as the hook normalizer records it."""

    payload: dict[str, object] = {
        "tool_name": "Bash",
        "tool_call_id": call,
        "success": success,
        "action": "claude_tool_success" if success else "claude_tool_failure",
    }
    if commitment is not None:
        payload["command_commitment"] = commitment
    return _envelope(event_kind, pos=pos, identity=f"hook:{call}:{pos}", payload=payload)


def _unresolved(*envelopes: ObservationEnvelope) -> list[ObservationAdviceCandidate]:
    return [
        item
        for item in observation_advice_findings(
            ObservationAdviceContext(
                envelopes=envelopes, lifecycle=ObservationLifecycle.ACTIVE, gaps=()
            )
        )
        if item.rule_code == "failed_command_unresolved"
    ]


def test_rerun_of_the_same_command_under_a_new_call_id_clears_the_failure() -> None:
    """A rerun is a new host call; the keyed command identity, not the call id, links it."""

    assert not _unresolved(
        _bash(1, "toolu-1", success=False, commitment=_PYTEST_X),
        _bash(2, "toolu-2", success=True, commitment=_PYTEST_X),
    )


def test_passing_run_of_a_different_command_keeps_the_failure_unresolved() -> None:
    unresolved = _unresolved(
        _bash(1, "toolu-1", success=False, commitment=_PYTEST_X),
        _bash(2, "toolu-2", success=True, commitment=_PYTEST_Y),
    )
    assert [item.evidence_refs for item in unresolved] == [("hook:toolu-1:1",)]


def test_completed_edit_after_a_failure_keeps_it_unresolved() -> None:
    edit = _envelope(
        "PostToolUse",
        pos=2,
        identity="hook:toolu-edit:2",
        payload={"tool_name": "Edit", "tool_call_id": "toolu-edit", "success": True},
    )
    assert _unresolved(_bash(1, "toolu-1", success=False, commitment=_PYTEST_X), edit)
    denied_edit = _envelope(
        "PostToolUse",
        pos=2,
        identity="hook:toolu-edit:2",
        payload={
            "tool_name": "Edit",
            "tool_call_id": "toolu-edit",
            "success": False,
            "denied": True,
        },
    )
    assert _unresolved(_bash(1, "toolu-1", success=False, commitment=_PYTEST_X), denied_edit)
    pending_edit = _envelope(
        "PreToolUse",
        pos=2,
        identity="hook:toolu-edit:2",
        payload={"tool_name": "Edit", "tool_call_id": "toolu-edit"},
    )
    assert _unresolved(_bash(1, "toolu-1", success=False, commitment=_PYTEST_X), pending_edit)


def test_legacy_envelopes_without_identity_stay_unresolved_after_edit() -> None:
    assert _unresolved(
        _bash(1, "toolu-1", success=False, commitment=None),
        _bash(2, "toolu-2", success=True, commitment=None),
    )
    edit = _envelope(
        "PostToolUse",
        pos=3,
        identity="hook:toolu-edit:3",
        payload={"tool_name": "Write", "tool_call_id": "toolu-edit", "success": True},
    )
    assert _unresolved(
        _bash(1, "toolu-1", success=False, commitment=None),
        _bash(2, "toolu-2", success=True, commitment=None),
        edit,
    )


def test_a_new_failure_after_the_pass_is_live_again() -> None:
    unresolved = _unresolved(
        _bash(1, "toolu-1", success=False, commitment=_PYTEST_X),
        _bash(2, "toolu-2", success=True, commitment=_PYTEST_X),
        _bash(3, "toolu-3", success=False, commitment=_PYTEST_X),
    )
    assert [item.evidence_refs for item in unresolved] == [("hook:toolu-3:3",)]


def test_a_permission_request_for_an_edit_tool_is_not_a_completed_edit() -> None:
    """Claude's PermissionRequest names the edit tool before it runs and may still be denied.

    Only a post-event materializes the ledger result the local packs read, so the advice must not
    retire a failure on a request the packs never see as an edit.
    """

    requested = _envelope(
        "PermissionRequest",
        pos=2,
        identity="hook:permission:2",
        payload={
            "tool_name": "Edit",
            "action": "claude_permission_request",
            "permission_decision": "requested",
        },
    )
    unresolved = _unresolved(_bash(1, "toolu-1", success=False, commitment=_PYTEST_X), requested)
    assert [item.evidence_refs for item in unresolved] == [("hook:toolu-1:1",)]


def test_only_the_latest_run_of_a_command_can_stay_unresolved() -> None:
    unresolved = _unresolved(
        _bash(1, "toolu-1", success=False, commitment=_PYTEST_X),
        _bash(2, "toolu-2", success=False, commitment=_PYTEST_X),
    )
    assert [item.evidence_refs for item in unresolved] == [("hook:toolu-2:2",)]
    rerun_without_outcome = _envelope(
        "PostToolUse",
        pos=2,
        identity="hook:toolu-2:2",
        payload={"tool_name": "Bash", "tool_call_id": "toolu-2", "command_commitment": _PYTEST_X},
    )
    assert _unresolved(
        _bash(1, "toolu-1", success=False, commitment=_PYTEST_X), rerun_without_outcome
    )


def test_cursor_ordinary_shell_failures_reach_the_rule_and_clear_on_rerun() -> None:
    """Cursor's ordinary profile names its shell tool ``Shell``; its exit code is structural."""

    def shell(pos: int, call: str, exit_status: int) -> ObservationEnvelope:
        return _envelope(
            "PostToolUse",
            pos=pos,
            identity=f"hook:{call}:{pos}",
            payload={
                "tool_name": "Shell",
                "tool_call_id": call,
                "exit_status": exit_status,
                "action": "cursor_tool_failure" if exit_status else "cursor_tool_success",
                "command_commitment": _PYTEST_X,
            },
        )

    assert [item.evidence_refs for item in _unresolved(shell(1, "cursor-1", 1))] == [
        ("hook:cursor-1:1",)
    ]
    assert not _unresolved(shell(1, "cursor-1", 1), shell(2, "cursor-2", 0))


def test_an_edit_post_event_without_a_stated_success_does_not_retire_a_failure() -> None:
    unknown_edit = _envelope(
        "PostToolUse",
        pos=2,
        identity="hook:cursor-edit:2",
        payload={
            "tool_name": "cursor_file_edit",
            "changed_paths_digest": "hmac-sha256:" + "c" * 64,
        },
    )
    unresolved = _unresolved(_bash(1, "toolu-1", success=False, commitment=_PYTEST_X), unknown_edit)
    assert [item.evidence_refs for item in unresolved] == [("hook:toolu-1:1",)]
