"""Integration-style tests for observation advice construction and wiring."""

from __future__ import annotations

import asyncio
import io
import json
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import get_args

from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.adapters.observation_semantic_advice import NullSemanticAdvice, OptionalSemanticAdvice
from finishup.application.observation_advice import (
    ObservationAdviceBuildInput,
    ObservationAdviceContextBuilder,
    ObservationAdviceSemanticAddon,
    advice_delivery_identity,
    build_observation_advice_snapshot,
    hook_advice_context,
    minimized_semantic_evidence_packet,
    select_advice_item,
    select_standing_item,
    semantic_state_from_addon,
    should_reissue_advice,
)
from finishup.application.observation_coordinator import (
    _materialized_advice_items,  # pyright: ignore[reportPrivateUsage]  # noqa: PLC2701
)
from finishup.cli.observe_hooks import handle_observe
from finishup.domain.observation import (
    AdviceSnapshot,
    ObservationCursor,
    ObservationEnvelope,
    ObservationLifecycle,
    ObservationSource,
    ObservationStatus,
    ObservationStatusQuery,
)
from finishup.domain.values import JsonObject, Timestamp, finding_id
from finishup.kernel.policies.observation_advice import (
    OBSERVATION_ADVICE_POLICY_ID,
    OBSERVATION_ADVICE_POLICY_VERSION,
    AdviceNextAction,
    ObservationAdviceContext,
    ObservationCompositionFact,
    evidence_basis_digest,
    observation_advice_findings,
)
from finishup.mcp.resources import read_resource

_COMMITMENT = "hmac-sha256:" + "a" * 64
_TIME = Timestamp("2026-07-22T21:00:00.000Z")


def _envelope(identity: str, payload: dict[str, object], *, pos: int = 1) -> ObservationEnvelope:
    return ObservationEnvelope(
        session_commitment=_COMMITMENT,
        event_kind="PostToolUse",
        source_identity=identity,
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=pos * 8,
            event_position=pos,
            last_source_commitment=_COMMITMENT,
            mapping_version="codex-obs-hook/1.0.0",
        ),
        receipt_time=_TIME,
        structural_payload=JsonObject(payload),
        content_object_refs=(),
        gap_codes=(),
    )


def test_zero_cooperative_publications_still_yields_advice() -> None:
    envelopes = (
        _envelope(
            "hook:fail",
            {"tool_name": "shell", "exit_status": 2, "correlation_id": "x1"},
        ),
    )
    snapshot = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            has_real_observation=True,
        )
    )
    assert snapshot is not None
    assert snapshot.ranked_finding_ids
    assert snapshot.ranked_items
    assert snapshot.ranked_items[0].rule_code == "failed_command_unresolved"
    assert snapshot.ranked_items[0].summary
    assert snapshot.recommended_next_action == "resolve_failed_command"
    assert "SECRET" not in snapshot.recommended_next_action


def _stale_finding_ids(envelopes: tuple[ObservationEnvelope, ...]) -> list[object]:
    snapshot = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            has_real_observation=True,
        )
    )
    assert snapshot is not None
    return [
        item.finding_id
        for item in _materialized_advice_items(snapshot.ranked_items)
        if item.rule_code == "edit_after_successful_check"
    ]


def test_paired_edit_mints_one_stable_advice_finding_id() -> None:
    """Issue #680: a paired host edit is one receipt-blocking condition."""

    check = _envelope(
        "hook:check",
        {"tool_name": "pytest", "exit_status": 0, "correlation_id": "check-1"},
        pos=1,
    )
    pre = replace(
        _envelope(
            "hook:write-pre",
            {
                "tool_name": "Write",
                "tool_call_id": "call-1",
                "action": "claude_tool_pending",
                "changed_paths_digest": "sha256:" + "b" * 64,
            },
            pos=2,
        ),
        event_kind="PreToolUse",
    )
    post = _envelope(
        "hook:write-post",
        {
            "tool_name": "Write",
            "tool_call_id": "call-1",
            "action": "claude_tool_success",
            "success": True,
            "changed_paths_digest": "sha256:" + "b" * 64,
        },
        pos=3,
    )
    paired = _stale_finding_ids((check, pre, post))
    assert len(paired) == 1
    # The later phase and the wider evidence window keep the same identity, so
    # the coordinator appends one ``finding_recorded`` event for this edit.
    assert _stale_finding_ids((check, pre)) == paired


def test_completion_without_verification_is_clear() -> None:
    envelopes = (
        _envelope(
            "hook:done",
            {"claim_kind": "completion", "result_status": "completed"},
            pos=1,
        ),
    )
    snapshot = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            has_real_observation=True,
        )
    )
    assert snapshot is not None
    assert any(
        item.rule_code == "completion_without_verification"
        and item.summary == "Completion not supported by current evidence"
        for item in snapshot.ranked_items
    )


def test_tool_completion_status_does_not_create_completion_advice() -> None:
    """Native tool outcomes are not authored completion claims."""

    snapshot = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=tuple(
                _envelope(
                    f"hook:tool-completed-{index}",
                    {"tool_name": "publish_work", "result_status": "completed"},
                    pos=index,
                )
                for index in range(1, 28)
            ),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            has_real_observation=True,
        )
    )
    assert snapshot is None


def test_completion_advice_bounds_refs_but_keeps_full_basis() -> None:
    envelopes = tuple(
        _envelope(
            f"hook:completion-{index:02d}",
            {"claim_kind": "completion"},
            pos=index,
        )
        for index in range(1, 18)
    )
    context = ObservationAdviceContext(
        envelopes=envelopes,
        lifecycle=ObservationLifecycle.ACTIVE,
        gaps=(),
    )
    candidates = observation_advice_findings(context)
    assert len(candidates) == 1
    assert len(candidates[0].evidence_refs) == 17
    snapshot = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            has_real_observation=True,
        )
    )
    assert snapshot is not None
    item = snapshot.ranked_items[0]
    assert len(item.evidence_refs) == 16
    assert item.evidence_refs == candidates[0].evidence_refs[:16]
    assert "advice_evidence_refs_truncated" in item.coverage.known_gaps
    assert snapshot.evidence_basis_digest == evidence_basis_digest(
        candidates,
        envelopes,
        extra={
            "policy": f"{OBSERVATION_ADVICE_POLICY_ID}/{OBSERVATION_ADVICE_POLICY_VERSION}",
            "lifecycle": "active",
            "coverage_gaps": ("advice_evidence_refs_truncated",),
        },
    )


def test_ranked_advice_bounds_findings_and_known_gaps() -> None:
    envelopes = tuple(
        _envelope(
            f"hook:failed-{index:02d}",
            {
                "tool_name": "shell",
                "exit_status": 1,
                "correlation_id": f"call-{index:02d}",
            },
            pos=index,
        )
        for index in range(1, 66)
    )
    snapshot = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=tuple(f"gap_{index:02d}" for index in range(64)),
            has_real_observation=True,
        )
    )
    assert snapshot is not None
    assert len(snapshot.ranked_finding_ids) == 64
    assert len(snapshot.ranked_items) == 64
    assert "advice_ranked_findings_truncated" in snapshot.confidence_coverage.known_gaps
    assert len(snapshot.confidence_coverage.known_gaps) == 64
    assert "advice_coverage_gaps_truncated" in snapshot.confidence_coverage.known_gaps
    candidates = observation_advice_findings(
        ObservationAdviceContext(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=tuple(f"gap_{index:02d}" for index in range(64)),
        )
    )
    assert snapshot.evidence_basis_digest == evidence_basis_digest(
        candidates,
        envelopes,
        extra={
            "policy": f"{OBSERVATION_ADVICE_POLICY_ID}/{OBSERVATION_ADVICE_POLICY_VERSION}",
            "lifecycle": "active",
            "coverage_gaps": tuple(
                sorted(
                    {
                        *(f"gap_{index:02d}" for index in range(64)),
                        "advice_ranked_findings_truncated",
                    },
                    key=str.encode,
                )
            ),
        },
    )


def test_semantic_addon_dedup_preserves_indexes_and_fences_invalid_text() -> None:
    first = finding_id("fnd_00000000-0000-4000-8000-000000000001")
    second = finding_id("fnd_00000000-0000-4000-8000-000000000002")
    addon = ObservationAdviceSemanticAddon(
        finding_ids=(first, first, second),
        evidence_digest="sha256:" + "c" * 64,
        summaries=("", "duplicate summary", "Second safe summary"),
        details=("/fixture/private-detail", "duplicate detail", "Second safe detail"),
    )
    snapshot = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=(_envelope("hook:failure", {"tool_name": "shell", "exit_status": 1}),),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            semantic_addon=addon,
            has_real_observation=True,
        )
    )
    assert snapshot is not None
    semantic_items = [
        item for item in snapshot.ranked_items if item.origin == "semantic_model_derived"
    ]
    assert [item.finding_id for item in semantic_items] == [first, second]
    assert semantic_items[0].summary == "Model-derived observation note"
    assert semantic_items[0].detail == "Additive AI-powered advice over minimized evidence"
    assert semantic_items[1].summary == "Second safe summary"
    assert semantic_items[1].detail == "Second safe detail"
    assert "advice_semantic_output_invalid" in semantic_items[0].coverage.known_gaps


def test_semantic_addon_skips_invalid_finding_ids_without_poisoning_valid_rows() -> None:
    valid = finding_id("fnd_00000000-0000-4000-8000-000000000003")
    addon = ObservationAdviceSemanticAddon(
        finding_ids=("invalid-finding-id", valid),  # type: ignore[arg-type]
        evidence_digest="sha256:" + "d" * 64,
        summaries=("bad row", "Valid row"),
        details=("bad row", "Valid detail"),
    )
    snapshot = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=(_envelope("hook:failure", {"tool_name": "shell", "exit_status": 1}),),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            semantic_addon=addon,
            has_real_observation=True,
        )
    )
    assert snapshot is not None
    semantic_items = [
        item for item in snapshot.ranked_items if item.origin == "semantic_model_derived"
    ]
    assert [item.finding_id for item in semantic_items] == [valid]
    assert semantic_items[0].summary == "Valid row"
    assert semantic_items[0].detail == "Valid detail"
    assert "advice_semantic_output_invalid" in semantic_items[0].coverage.known_gaps


def test_semantic_only_invalid_next_action_falls_back_before_snapshot_validation() -> None:
    finding = finding_id("fnd_00000000-0000-4000-8000-000000000004")
    snapshot = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=(),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            semantic_addon=ObservationAdviceSemanticAddon(
                finding_ids=(finding,),
                evidence_digest="sha256:" + "e" * 64,
                next_action="/fixture/private-action",
                summaries=("Provider note",),
                details=("Provider detail",),
            ),
        )
    )
    assert snapshot is not None
    assert snapshot.recommended_next_action == "reground_status"
    assert snapshot.ranked_items[0].recommended_next_action == "reground_status"
    assert "advice_semantic_output_invalid" in snapshot.confidence_coverage.known_gaps


def test_semantic_only_invalid_finding_ids_yield_deterministic_gap_advice() -> None:
    snapshot = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=(),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            semantic_addon=ObservationAdviceSemanticAddon(
                finding_ids=("invalid-finding-id",),  # type: ignore[arg-type]
                evidence_digest="sha256:" + "f" * 64,
                summaries=("Provider note",),
                details=("Provider detail",),
            ),
        )
    )
    assert snapshot is not None
    assert len(snapshot.ranked_items) == 1
    item = snapshot.ranked_items[0]
    assert item.origin == "deterministic"
    assert item.rule_code == "observation_gap_or_stale"
    assert item.recommended_next_action == "reground_status"
    assert "advice_semantic_output_invalid" in item.coverage.known_gaps


def test_semantic_text_clipping_is_an_explicit_coverage_gap() -> None:
    finding = finding_id("fnd_00000000-0000-4000-8000-000000000005")
    summary = "Summary " + "s" * 200
    detail = "Detail " + "d" * 300
    snapshot = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=(),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            semantic_addon=ObservationAdviceSemanticAddon(
                finding_ids=(finding,),
                evidence_digest="sha256:" + "a" * 64,
                summaries=(summary,),
                details=(detail,),
            ),
        )
    )
    assert snapshot is not None
    item = snapshot.ranked_items[0]
    assert len(item.summary) == 160
    assert len(item.detail) == 240
    assert item.summary == summary[:160]
    assert item.detail == detail[:240]
    assert "advice_semantic_text_truncated" in item.coverage.known_gaps
    assert "advice_semantic_output_invalid" not in item.coverage.known_gaps
    assert snapshot.evidence_basis_digest == evidence_basis_digest(
        (),
        (),
        extra={
            "policy": f"{OBSERVATION_ADVICE_POLICY_ID}/{OBSERVATION_ADVICE_POLICY_VERSION}",
            "lifecycle": "active",
            "coverage_gaps": ("advice_semantic_text_truncated",),
            "semantic_evidence": "sha256:" + "a" * 64,
        },
    )


def test_semantic_state_from_addon_uses_attempt_status_not_finding_count() -> None:
    assert semantic_state_from_addon(None) == "disabled"
    pending = ObservationAdviceSemanticAddon(
        finding_ids=(),
        evidence_digest=None,
        failure_reason="pending",
    )
    failed = ObservationAdviceSemanticAddon(
        finding_ids=(),
        evidence_digest=None,
        failure_reason="transport_unavailable",
    )
    succeeded_empty = ObservationAdviceSemanticAddon(
        finding_ids=(),
        evidence_digest="sha256:" + "b" * 64,
        summaries=(),
        details=(),
    )
    succeeded_with_findings = ObservationAdviceSemanticAddon(
        finding_ids=(finding_id("fnd_00000000-0000-4000-8000-000000000009"),),
        evidence_digest="sha256:" + "c" * 64,
        summaries=("note",),
        details=("detail",),
    )
    assert semantic_state_from_addon(pending) == "unavailable"
    assert semantic_state_from_addon(failed) == "failed"
    assert semantic_state_from_addon(succeeded_empty) == "ready"
    assert semantic_state_from_addon(succeeded_with_findings) == "ready"


def test_successful_empty_review_is_ready_not_disabled() -> None:
    envelope = _envelope(
        "hook:fail", {"tool_name": "shell", "exit_status": 2, "correlation_id": "x1"}
    )
    disabled = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=(envelope,),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            has_real_observation=True,
        )
    )
    ready = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=(envelope,),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            has_real_observation=True,
            semantic_addon=ObservationAdviceSemanticAddon(
                finding_ids=(),
                evidence_digest="sha256:" + "b" * 64,
                summaries=(),
                details=(),
            ),
        )
    )
    assert disabled is not None
    assert ready is not None
    assert disabled.semantic_attempt_state == "disabled"
    assert ready.semantic_attempt_state == "ready"
    assert not any(item.origin == "semantic_model_derived" for item in ready.ranked_items)
    # The attempt state is not coverage: only validated finding ids add the AI-powered check type
    # (docs/INTERFACES.md), so a zero-finding review stays an honest receipt, not a finding.
    assert "semantic_model_derived" not in {
        check.value for check in ready.confidence_coverage.check_types
    }
    assert should_reissue_advice(disabled, ready)


def test_attempt_state_change_reissues_even_with_unchanged_suppression_identity() -> None:
    envelope = _envelope(
        "hook:fail", {"tool_name": "shell", "exit_status": 2, "correlation_id": "x1"}
    )
    disabled = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=(envelope,),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            has_real_observation=True,
        )
    )
    assert disabled is not None
    # A review that completes with no findings and no evidence digest changes neither the basis
    # nor the suppression identity; only the recorded attempt state moves.
    ready = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=(envelope,),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            has_real_observation=True,
            prior_snapshot=disabled,
            semantic_addon=ObservationAdviceSemanticAddon(finding_ids=(), evidence_digest=None),
        )
    )
    assert ready is not None
    assert ready.suppression_identity == disabled.suppression_identity
    assert ready.semantic_attempt_state == "ready"


def test_invalid_semantic_only_output_is_a_failed_attempt_without_coverage() -> None:
    snapshot = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=(),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            semantic_addon=ObservationAdviceSemanticAddon(
                finding_ids=("invalid-finding-id",),  # type: ignore[arg-type]
                evidence_digest="sha256:" + "f" * 64,
                summaries=("Provider note",),
                details=("Provider detail",),
            ),
        )
    )
    assert snapshot is not None
    assert "advice_semantic_output_invalid" in snapshot.confidence_coverage.known_gaps
    assert "semantic_model_derived" not in {
        check.value for check in snapshot.confidence_coverage.check_types
    }
    assert snapshot.semantic_attempt_state == "failed"


def test_empty_semantic_result_does_not_create_deterministic_fallback() -> None:
    snapshot = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=(),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            semantic_addon=ObservationAdviceSemanticAddon(
                finding_ids=(),
                evidence_digest="sha256:" + "b" * 64,
                summaries=(),
                details=(),
            ),
        )
    )
    assert snapshot is None


def test_standing_provider_condition_keeps_one_candidate_identity_as_envelopes_grow() -> None:
    composition = ObservationCompositionFact(
        semantic_configured=True,
        semantic_ready=False,
        provider_factory_ids=("provider-a",),
        connected_provider_ids=(),
    )
    first = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=(_envelope("hook:one", {"tool_name": "shell"}),),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            composition=composition,
            has_real_observation=True,
        )
    )
    many = tuple(
        _envelope(f"hook:{index}", {"tool_name": "shell"}, pos=index) for index in range(1, 21)
    )
    latest = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=many,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            composition=composition,
            has_real_observation=True,
        )
    )
    assert first is not None and latest is not None
    first_provider = next(
        item for item in first.ranked_items if item.rule_code == "provider_not_ready"
    )
    latest_provider = next(
        item for item in latest.ranked_items if item.rule_code == "provider_not_ready"
    )
    assert latest_provider.finding_id == first_provider.finding_id
    assert latest.evidence_basis_digest != first.evidence_basis_digest
    assert latest_provider not in _materialized_advice_items(latest.ranked_items)
    # #241: the delivery identity is over what the agent actually receives, so
    # it must NOT move with the envelope stream the basis digest tracks.
    assert advice_delivery_identity(first) == advice_delivery_identity(latest)


def test_callable_composition_is_resolved_freshly_on_every_build() -> None:
    """The provider fact is recomputed per build, tracking live machine state (#265).

    A READY-frozen fact kept advising connect_provider after the same mapped
    session dispatched successfully. A per-build source lets current structural
    usability retire the advice and credential revocation resurface it.
    """

    facts = [
        ObservationCompositionFact(
            semantic_configured=True,
            semantic_ready=False,
            provider_factory_ids=("fireworks",),
            connected_provider_ids=(),
        ),
        ObservationCompositionFact(
            semantic_configured=True,
            semantic_ready=True,
            provider_factory_ids=("fireworks",),
            connected_provider_ids=("fireworks",),
        ),
        ObservationCompositionFact(
            semantic_configured=True,
            semantic_ready=False,
            provider_factory_ids=("fireworks",),
            connected_provider_ids=(),
        ),
    ]
    builds: list[ObservationCompositionFact] = []

    async def composition() -> ObservationCompositionFact:
        fact = facts[len(builds)]
        builds.append(fact)
        return fact

    class _Store:
        def list_envelopes(self, workspace: str) -> tuple[ObservationEnvelope, ...]:
            del workspace
            return (_envelope("hook:one", {"tool_name": "shell"}),)

        async def status(self, query: ObservationStatusQuery) -> ObservationStatus:
            del query
            return ObservationStatus(
                ObservationLifecycle.ACTIVE,
                _COMMITMENT,
                {},
                _TIME,
                0,
                (),
                (),
                None,
            )

        def load_advice_snapshot(self, workspace: str) -> None:
            del workspace
            return None

    builder = ObservationAdviceContextBuilder(composition=composition)

    def rule_codes(snapshot: object) -> tuple[str, ...]:
        if snapshot is None:
            return ()
        assert isinstance(snapshot, AdviceSnapshot)
        return tuple(item.rule_code for item in snapshot.ranked_items)

    missing = asyncio.run(builder.build(_COMMITMENT, _Store()))  # type: ignore[arg-type]
    connected = asyncio.run(builder.build(_COMMITMENT, _Store()))  # type: ignore[arg-type]
    revoked = asyncio.run(builder.build(_COMMITMENT, _Store()))  # type: ignore[arg-type]

    assert len(builds) == 3, "the composition source was not consulted on every build"
    assert "provider_not_ready" in rule_codes(missing)
    assert "provider_not_ready" not in rule_codes(connected)
    assert "provider_not_ready" in rule_codes(revoked)


def test_mapped_build_uses_session_scoped_envelopes_and_health() -> None:
    """#352: a mapped session snapshot is built from that session's evidence and
    current health, never from workspace-wide history."""

    session_a = "hmac-sha256:" + "b" * 64
    session_b = "hmac-sha256:" + "c" * 64

    def _session_envelope(
        session: str, identity: str, payload: dict[str, object], pos: int
    ) -> ObservationEnvelope:
        base = _envelope(identity, payload, pos=pos)
        return ObservationEnvelope(
            session_commitment=session,
            event_kind=base.event_kind,
            source_identity=base.source_identity,
            source=base.source,
            cursor=base.cursor,
            receipt_time=base.receipt_time,
            structural_payload=base.structural_payload,
            content_object_refs=base.content_object_refs,
            gap_codes=base.gap_codes,
        )

    # Session A carries an unresolved failure and degraded health; session B
    # carries only its own completion-without-verification condition.
    failed_a = _session_envelope(
        session_a, "hook:fail-a", {"tool_name": "shell", "exit_status": 2, "tool_call_id": "a1"}, 1
    )
    claim_b = _session_envelope(
        session_b, "hook:claim-b", {"claim_kind": "completion", "result_status": "completed"}, 2
    )

    class _Store:
        def __init__(self) -> None:
            self.workspace_reads = 0

        def list_envelopes(self, workspace: str) -> tuple[ObservationEnvelope, ...]:
            del workspace
            self.workspace_reads += 1
            return (failed_a, claim_b)

        def list_envelopes_for_session(
            self, workspace: str, session_commitment: str
        ) -> tuple[ObservationEnvelope, ...]:
            del workspace
            return tuple(
                env for env in (failed_a, claim_b) if env.session_commitment == session_commitment
            )

        async def status(self, query: ObservationStatusQuery) -> ObservationStatus:
            self.workspace_reads += 1
            return ObservationStatus(
                ObservationLifecycle.STALE,
                query.workspace_commitment,
                {},
                _TIME,
                0,
                ("observation_storage_corrupt", "source_lag"),
                (),
                None,
            )

        async def status_for_session(
            self, workspace: str, session_commitment: str
        ) -> ObservationStatus:
            del workspace
            degraded = session_commitment == session_a
            return ObservationStatus(
                ObservationLifecycle.STALE if degraded else ObservationLifecycle.ACTIVE,
                _COMMITMENT,
                {},
                _TIME,
                0,
                ("observation_storage_corrupt", "source_lag") if degraded else (),
                (),
                None,
            )

        def load_advice_snapshot(self, workspace: str) -> None:
            del workspace
            return None

    def rule_codes(snapshot: object) -> tuple[str, ...]:
        if snapshot is None:
            return ()
        assert isinstance(snapshot, AdviceSnapshot)
        return tuple(item.rule_code for item in snapshot.ranked_items)

    builder = ObservationAdviceContextBuilder()
    store = _Store()
    snapshot_b = asyncio.run(
        builder.build(_COMMITMENT, store, session_commitment=session_b)  # type: ignore[arg-type]
    )
    codes_b = rule_codes(snapshot_b)
    # B's own condition is visible; A's failure and A's degraded health are not.
    assert "completion_without_verification" in codes_b
    assert "failed_command_unresolved" not in codes_b
    assert "observation_gap_or_stale" not in codes_b
    assert store.workspace_reads == 0, "a mapped build must not read workspace-wide inputs"

    snapshot_a = asyncio.run(
        builder.build(_COMMITMENT, store, session_commitment=session_a)  # type: ignore[arg-type]
    )
    codes_a = rule_codes(snapshot_a)
    # A's real degradation stays visible and actionable in A's own snapshot.
    assert "failed_command_unresolved" in codes_a
    assert "observation_gap_or_stale" in codes_a

    # Without a session commitment (unmapped build), workspace-wide behavior
    # is unchanged for the operator surface.
    aggregate = asyncio.run(builder.build(_COMMITMENT, store))  # type: ignore[arg-type]
    assert store.workspace_reads == 2
    assert "failed_command_unresolved" in rule_codes(aggregate)


def test_delivery_identity_is_stable_while_the_envelope_stream_grows() -> None:
    """The hook-channel identity keys on rendered content, not on evidence breadth."""

    composition = ObservationCompositionFact(
        semantic_configured=True,
        semantic_ready=False,
        provider_factory_ids=("fireworks",),
        connected_provider_ids=(),
    )

    def _build(count: int):
        built = build_observation_advice_snapshot(
            ObservationAdviceBuildInput(
                envelopes=tuple(
                    _envelope(f"hook:{index}", {"tool_name": "shell"}, pos=index)
                    for index in range(1, count + 1)
                ),
                lifecycle=ObservationLifecycle.ACTIVE,
                gaps=(),
                composition=composition,
                has_real_observation=True,
            )
        )
        assert built is not None
        return built

    one = _build(1)
    twenty = _build(20)
    assert advice_delivery_identity(one) == advice_delivery_identity(twenty)
    assert one.evidence_basis_digest != twenty.evidence_basis_digest
    assert hook_advice_context(one) == hook_advice_context(twenty)


def _gap_snapshot(count: int):
    """Gap advice over ``count`` envelopes; its evidence refs are the last three."""

    built = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=tuple(
                _envelope(f"hook:gap{index}", {"tool_name": "Read"}, pos=index)
                for index in range(1, count + 1)
            ),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=("source_lag",),
            has_real_observation=True,
        )
    )
    assert built is not None
    assert built.ranked_items[0].rule_code == "observation_gap_or_stale"
    return built


def test_delivery_identity_ignores_evidence_refs_that_are_a_rolling_window() -> None:
    """A rule may cite the last three envelopes; that citation is not a new condition.

    ``observation_gap_or_stale`` cites ``envelopes[-3:]``, so an identity that
    folded in the evidence ref moved on every single hook and stormed exactly
    like the standing condition #241 fixed (measured: delivered on 12 of 12
    consecutive PostToolUse hooks).
    """

    first = _gap_snapshot(3)
    later = _gap_snapshot(9)

    assert first.ranked_items[0].evidence_refs != later.ranked_items[0].evidence_refs
    # The delivered text cites the live cause, which leads the sorted refs (#917);
    # the rolling envelope window still travels with the item.
    assert first.ranked_items[0].evidence_refs[0] == "cause:source_lag"
    assert "Evidence: cause:source_lag." in hook_advice_context(later)
    assert advice_delivery_identity(first) == advice_delivery_identity(later), (
        "the dedup key moved with a rolling evidence window; the advice will storm"
    )


def test_hook_advice_context_maps_refresh_observation_to_observe_status() -> None:
    """Issue #323: the hook clause must name a real host-shell step, not a fake tool."""

    snapshot = _gap_snapshot(3)
    item = snapshot.ranked_items[0]
    assert item.recommended_next_action == "refresh_observation"
    text = hook_advice_context(snapshot)
    assert "finishup observe status" in text
    assert "Next: refresh_observation" not in text
    assert item.evidence_refs[0] in text
    assert len(text) <= 512
    # Issue #911: a standing host-profile gap (Codex `unpaired_event`) never recovers in-session,
    # so the clause must not ask the agent to wait for it, answer it, or recheck for it.
    assert "wait for drain to recover" not in text
    assert "wait only while it reports lag or a drain backlog" in text
    assert "standing limitation: it needs no response or recheck" in text
    assert "never blocks the receipt" in text
    # A production-length hook reference still fits the bounded context whole.
    long_refs = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=tuple(
                _envelope(f"hook:{index:064x}", {"tool_name": "Read"}, pos=index)
                for index in range(1, 4)
            ),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=("source_lag",),
            has_real_observation=True,
        )
    )
    assert long_refs is not None
    long_text = hook_advice_context(long_refs)
    assert long_text.endswith(f"Evidence: {long_refs.ranked_items[0].evidence_refs[0]}.")
    assert len(long_text) <= 512


def test_hook_advice_context_keeps_work_next_action_tokens() -> None:
    snapshot = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=(
                _envelope(
                    "hook:fail",
                    {"tool_name": "shell", "exit_status": 2, "correlation_id": "x1"},
                ),
            ),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            has_real_observation=True,
        )
    )
    assert snapshot is not None
    assert snapshot.recommended_next_action == "resolve_failed_command"
    assert "Next: resolve_failed_command" in hook_advice_context(snapshot)


def test_workflow_guidance_documents_advice_next_action_tokens() -> None:
    text = read_resource("finishup://guidance/workflow.md").decode("utf-8")
    for token in get_args(AdviceNextAction.__value__):
        assert f"`{token}`" in text, token
    assert "`finishup observe status`" in text
    assert "not MCP tools" in text


def test_finding_identity_ignores_evidence_refs_that_are_a_rolling_window() -> None:
    """A standing condition remains one durable finding as its citations move (#216)."""

    first = _gap_snapshot(3)
    later = _gap_snapshot(9)

    assert first.ranked_items[0].evidence_refs != later.ranked_items[0].evidence_refs
    assert first.evidence_basis_digest != later.evidence_basis_digest
    assert first.ranked_items[0].finding_id == later.ranked_items[0].finding_id


def test_delivery_identity_distinguishes_successive_failed_commands() -> None:
    shared_prefix = "same-correlation-prefix-" + "x" * 40
    first = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=(
                _envelope(
                    "hook:fail-a",
                    {
                        "tool_name": "shell",
                        "exit_status": 2,
                        "correlation_id": shared_prefix + "-a",
                    },
                ),
            ),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            has_real_observation=True,
        )
    )
    later = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=(
                _envelope(
                    "hook:fail-a",
                    {
                        "tool_name": "shell",
                        "exit_status": 2,
                        "correlation_id": shared_prefix + "-a",
                    },
                    pos=1,
                ),
                _envelope(
                    "hook:resolve-a",
                    {
                        "tool_name": "shell",
                        "exit_status": 0,
                        "correlation_id": shared_prefix + "-a",
                    },
                    pos=2,
                ),
                _envelope(
                    "hook:fail-b",
                    {
                        "tool_name": "shell",
                        "exit_status": 3,
                        "correlation_id": shared_prefix + "-b",
                    },
                    pos=3,
                ),
            ),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            has_real_observation=True,
        )
    )
    assert first is not None and later is not None
    assert first.ranked_items[0].summary == later.ranked_items[0].summary
    assert first.ranked_items[0].finding_id != later.ranked_items[0].finding_id
    assert advice_delivery_identity(first) != advice_delivery_identity(later)


def test_delivery_identity_changes_with_rule_code_or_next_action() -> None:
    """Everything that names the condition stays in the key."""

    import dataclasses

    snapshot = _gap_snapshot(3)
    item = snapshot.ranked_items[0]
    baseline = advice_delivery_identity(snapshot, item=item)

    other_rule = dataclasses.replace(item, rule_code="provider_not_ready")
    other_action = dataclasses.replace(item, recommended_next_action="connect_provider")
    other_summary = dataclasses.replace(item, summary="A different summary")
    other_detail = dataclasses.replace(item, detail="A different detail")
    for changed in (other_rule, other_action, other_summary, other_detail):
        assert advice_delivery_identity(snapshot, item=changed) != baseline


def test_delivery_identity_changes_when_the_rendered_text_changes() -> None:
    standing = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=(_envelope("hook:one", {"tool_name": "shell"}),),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            composition=ObservationCompositionFact(
                semantic_configured=True,
                semantic_ready=False,
                provider_factory_ids=("fireworks",),
                connected_provider_ids=(),
            ),
            has_real_observation=True,
        )
    )
    failed = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=(
                _envelope(
                    "hook:one",
                    {"tool_name": "shell", "exit_status": 1, "correlation_id": "x1"},
                ),
            ),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            has_real_observation=True,
        )
    )
    assert standing is not None and failed is not None
    assert hook_advice_context(standing) != hook_advice_context(failed)
    assert advice_delivery_identity(standing) != advice_delivery_identity(failed)


def test_standing_items_fall_through_to_the_first_actionable_item() -> None:
    """Withholding a standing item must never suppress advice ranked below it."""

    snapshot = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=(_envelope("hook:one", {"tool_name": "shell", "claim_kind": "semantic"}),),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            composition=ObservationCompositionFact(
                semantic_configured=True,
                semantic_ready=False,
                provider_factory_ids=("fireworks",),
                connected_provider_ids=(),
            ),
            has_real_observation=True,
        )
    )
    assert snapshot is not None
    assert [item.rule_code for item in snapshot.ranked_items] == [
        "provider_not_ready",
        "semantic_claim_without_attempt",
    ]
    permitted = select_advice_item(snapshot, allow_standing=True)
    withheld = select_advice_item(snapshot, allow_standing=False)
    standing = select_standing_item(snapshot)
    assert permitted is not None and permitted.rule_code == "provider_not_ready"
    assert withheld is not None and withheld.rule_code == "semantic_claim_without_attempt"
    assert standing is not None and standing.rule_code == "provider_not_ready"


def test_suppression_identity_still_tracks_evidence_for_materialization() -> None:
    """observation_advice_history keys row distinctness on evidence; do not weaken it.

    ``suppression_identity`` also carries the coordinator's materialization
    retry-safety and ``observe status``'s advice_frontier, so the #241 fix adds
    a second identity rather than redefining this one.
    """

    composition = ObservationCompositionFact(
        semantic_configured=True,
        semantic_ready=False,
        provider_factory_ids=("fireworks",),
        connected_provider_ids=(),
    )

    def _build(count: int):
        built = build_observation_advice_snapshot(
            ObservationAdviceBuildInput(
                envelopes=tuple(
                    _envelope(f"hook:{index}", {"tool_name": "shell"}, pos=index)
                    for index in range(1, count + 1)
                ),
                lifecycle=ObservationLifecycle.ACTIVE,
                gaps=(),
                composition=composition,
                has_real_observation=True,
            )
        )
        assert built is not None
        return built

    narrow = _build(1)
    broad = _build(5)
    assert narrow.ranked_finding_ids == broad.ranked_finding_ids
    assert narrow.suppression_identity != broad.suppression_identity


def test_semantic_packet_minimization() -> None:
    envelopes = (
        _envelope(
            "hook:fail",
            {"tool_name": "shell", "exit_status": 1, "correlation_id": "x1"},
        ),
    )
    candidates = observation_advice_findings(
        ObservationAdviceContext(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=("source_lag",),
        )
    )
    packet = minimized_semantic_evidence_packet(
        candidates,
        "sha256:" + "e" * 64,
        coverage_gaps=("source_lag",),
        finding_summaries=("Unresolved failed command observed",),
    )
    assert "transcript" not in packet
    assert "stdout" not in packet
    assert "path" not in packet
    assert packet["coverage_gaps"] == ("source_lag",)
    serialized = str(packet)
    assert "/Users" not in serialized
    assert "SECRET" not in serialized


def test_suppression_skips_duplicate_until_evidence_changes() -> None:
    envelopes = (
        _envelope(
            "hook:fail",
            {"tool_name": "shell", "exit_status": 1, "correlation_id": "x1"},
        ),
    )
    first = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            has_real_observation=True,
        )
    )
    assert first is not None
    second = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            prior_snapshot=first,
            has_real_observation=True,
        )
    )
    assert second is first
    assert should_reissue_advice(first, first) is False
    changed = (
        envelopes[0],
        _envelope(
            "hook:fail2",
            {"tool_name": "shell", "exit_status": 1, "correlation_id": "x2"},
            pos=2,
        ),
    )
    third = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=changed,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            prior_snapshot=first,
            has_real_observation=True,
        )
    )
    assert third is not None
    assert third.suppression_identity != first.suppression_identity


def test_deterministic_only_vs_configured_semantic() -> None:
    envelopes = (
        _envelope(
            "hook:fail",
            {"tool_name": "shell", "exit_status": 1, "correlation_id": "x1"},
        ),
    )
    candidates = observation_advice_findings(
        ObservationAdviceContext(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
        )
    )
    packet = minimized_semantic_evidence_packet(candidates, "sha256:" + "e" * 64)
    assert "transcript" not in packet
    assert "stdout" not in packet
    null = NullSemanticAdvice().review(evidence_packet=packet)
    assert null is None

    def _eval(payload: Mapping[str, object]) -> Mapping[str, object]:
        assert "transcript" not in payload
        return {"detail_token": "sem-1", "next_action": "reground_status"}

    addon = OptionalSemanticAdvice(configured=True, ready=True, evaluator=_eval).review(
        evidence_packet=packet
    )
    assert addon is not None
    snapshot = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            semantic_addon=addon,
            has_real_observation=True,
        )
    )
    assert snapshot is not None
    assert len(snapshot.ranked_finding_ids) >= 2


def test_semantic_observation_review_receives_the_trusted_finishup_session() -> None:
    session_id = "ses_00000000-0000-4000-8000-000000000001"
    observed: list[str | None] = []

    class _Store:
        def list_envelopes(self, workspace: str) -> tuple[ObservationEnvelope, ...]:
            assert workspace == _COMMITMENT
            return (
                _envelope(
                    "hook:fail",
                    {"tool_name": "shell", "exit_status": 1, "correlation_id": "x1"},
                ),
            )

        async def status(self, query: ObservationStatusQuery) -> ObservationStatus:
            assert query.workspace_commitment == _COMMITMENT
            return ObservationStatus(
                ObservationLifecycle.ACTIVE,
                _COMMITMENT,
                {},
                _TIME,
                0,
                (),
                (),
                None,
            )

        def load_advice_snapshot(self, workspace: str) -> None:
            assert workspace == _COMMITMENT
            return None

    async def review(
        candidates: object, basis: str, gaps: tuple[str, ...], finishup_session_id: str | None
    ) -> None:
        del candidates, basis, gaps
        observed.append(finishup_session_id)

    builder = ObservationAdviceContextBuilder(semantic_review=review)  # type: ignore[arg-type]
    snapshot = asyncio.run(
        builder.build(_COMMITMENT, _Store(), finishup_session_id=session_id)  # type: ignore[arg-type]
    )

    assert snapshot is not None
    assert observed == [session_id]


def test_observe_hook_refresh_advice_without_mcp_tools(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    out = io.BytesIO()
    code = handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {
                "session_id": "advice-1",
                "tool_name": "shell",
                "correlation_id": "c-fail",
                "exit_status": 1,
            }
        ).encode(),
        stdout=out,
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    assert code == 0
    status = store.status(ObservationStatusQuery(workspace))
    assert status.advice_frontier is not None
    payload = json.loads(out.getvalue().decode() or "{}")
    # Safe-event delivery consumes the snapshot once into additionalContext.
    context = payload.get("hookSpecificOutput") or payload
    serialized = json.dumps(payload)
    assert "resolve_failed_command" in serialized or status.advice_frontier != "none"
    # Second peek is suppressed (same evidence frontier).
    assert (
        store.peek_advice_for_delivery(
            workspace, session_commitment=store.session_commitment("advice-1")
        )
        is None
    )
    _ = context
    text = serialized
    assert "AKIA" not in text
    assert "password" not in text.lower()


def test_secret_like_command_output_absent_from_advice_surfaces(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {
                "session_id": "advice-2",
                "tool_name": "shell",
                "exit_status": 1,
                "stdout": "AWS_SECRET=should-never-appear",
                "transcript": "hidden reasoning with password=hunter2",
            }
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    snapshot = store.refresh_advice(
        workspace,
        composition=ObservationCompositionFact(
            semantic_configured=False,
            semantic_ready=False,
            provider_factory_ids=(),
            connected_provider_ids=(),
        ),
    )
    assert snapshot is not None
    encoded = repr(snapshot)
    assert "AWS_SECRET" not in encoded
    assert "hunter2" not in encoded
    assert "password" not in encoded


def _attention_snapshot(token: str) -> AdviceSnapshot:
    snapshot = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=(_envelope("hook:one", {"tool_name": "shell"}),),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            composition=ObservationCompositionFact(
                semantic_configured=True,
                semantic_ready=True,
                provider_factory_ids=("openai-codex",),
                connected_provider_ids=("openai-codex",),
                semantic_attention=token,
                semantic_attention_provider="openai-codex",
            ),
            has_real_observation=True,
        )
    )
    assert snapshot is not None
    return snapshot


def test_codex_sign_in_attention_tells_the_agent_to_involve_the_user() -> None:
    """An expired Codex login reaches the agent as actionable standing advice (#819)."""

    snapshot = _attention_snapshot("sign_in_required")
    item = select_standing_item(snapshot)
    assert item is not None
    assert item.rule_code == "semantic_sign_in_required"
    assert item.recommended_next_action == "renew_provider_sign_in"
    # Standing machine conditions never ride the per-tool channel or the task ledger.
    assert select_advice_item(snapshot, allow_standing=False) is not item
    assert item not in _materialized_advice_items(snapshot.ranked_items)

    text = hook_advice_context(snapshot, item=item)
    assert len(text) <= 512
    assert text.startswith("FinishUP: AI-powered review needs the user to sign in to Codex again.")
    assert "Next: renew_provider_sign_in. Tell the user now." in text
    assert "subagent" in text
    assert "`finishup provider codex-subscription setup`" in text
    assert "`--device-code`" in text
    assert "the user completes sign-in" in text
    assert text.endswith("Evidence: openai-codex.")


def test_each_repairable_cause_renders_its_own_reason_and_repair() -> None:
    expectations = {
        "credential_rejected": ("stored credential", "`finishup provider status`"),
        "access_denied": ("account or plan", "`finishup provider status`"),
        "quota_exhausted": ("usage quota exhausted", "`finishup provider status`"),
        "model_unavailable": ("no longer offered", "`finishup provider status`"),
        "runtime_update_required": (
            "newer FinishUP release",
            "restart Codex, Claude Code, or Cursor",
        ),
    }
    texts: set[str] = set()
    for token, (reason, repair) in expectations.items():
        snapshot = _attention_snapshot(token)
        item = select_standing_item(snapshot)
        assert item is not None and item.rule_code == "semantic_provider_attention"
        text = hook_advice_context(snapshot, item=item)
        assert len(text) <= 512
        assert reason in item.detail
        assert repair in text
        assert "Tell the user now." in text
        texts.add(advice_delivery_identity(snapshot, item=item))
    # A changed cause is a changed condition, so it is delivered again rather than suppressed.
    assert len(texts) == len(expectations)


def test_connect_provider_keeps_its_token_and_gains_a_user_facing_repair() -> None:
    snapshot = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
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
    )
    assert snapshot is not None
    text = hook_advice_context(snapshot, item=select_standing_item(snapshot))
    assert "Next: connect_provider. Tell the user now." in text
    assert "`finishup provider status`" in text


def test_model_derived_advice_cannot_claim_an_attempt_derived_repair() -> None:
    """Only the service's own attempt outcomes may tell the user to sign in or update."""

    finding = finding_id("fnd_00000000-0000-4000-8000-000000000819")
    snapshot = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=(),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            semantic_addon=ObservationAdviceSemanticAddon(
                finding_ids=(finding,),
                evidence_digest="sha256:" + "e" * 64,
                next_action="renew_provider_sign_in",
                summaries=("Provider note",),
                details=("Provider detail",),
            ),
        )
    )
    assert snapshot is not None
    assert snapshot.recommended_next_action == "reground_status"
    assert all(
        item.recommended_next_action != "renew_provider_sign_in" for item in snapshot.ranked_items
    )
    assert "advice_semantic_output_invalid" in snapshot.confidence_coverage.known_gaps
