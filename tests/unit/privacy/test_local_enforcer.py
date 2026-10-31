"""Provider-free deterministic privacy enforcement tests."""

from __future__ import annotations

import base64
import json
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from finishup.adapters.privacy.local_enforcer import (
    LocalPrivacyEnforcer,
    scan_exact_bytes,
    scan_exact_bytes_with_confidence,
)
from finishup.application.egress import (
    PrivacyCoordinator,
    _heuristic_only_item_ids,  # pyright: ignore[reportPrivateUsage]
)
from finishup.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    CandidateContext,
    CandidateContextItem,
    ChannelPolicy,
    ClassifiedContext,
    DataClass,
    DisclosureProvenance,
    EgressChannel,
    ForbiddenDataKind,
    LocalDisclosureSink,
    PrivacyDecision,
    PrivacyOutcome,
    PrivacyPolicy,
    PrivacyProfile,
    PrivacyReason,
    ProjectionProvenanceContext,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from finishup.domain.values import Frontier
from finishup.ports.privacy import EffectivePrivacyPolicy, MinimizedDisclosure
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.models import DataCategory

_INSTALLATION = "ins_10000000-0000-4000-8000-000000000001"
_TASK = "tsk_10000000-0000-4000-8000-000000000002"
_OTHER_TASK = "tsk_10000000-0000-4000-8000-000000000007"
_REQUEST = "req_10000000-0000-4000-8000-000000000003"
_WORKSPACE = f"hmac-sha256:{'1' * 64}"
_DIGEST = f"sha256:{'2' * 64}"
_NOW = datetime(2026, 7, 19, tzinfo=UTC)
_SESSION = "ses_10000000-0000-4000-8000-000000000005"
_WRITER = "wri_10000000-0000-4000-8000-000000000006"
_FRONTIER = Frontier(3, f"sha256:{'3' * 64}")


def _scope() -> AuthorizationScope:
    return AuthorizationScope(
        AuthorizationScopeKind.TASK,
        _INSTALLATION,
        _WORKSPACE,
        _TASK,
    )


def _disabled(channel: EgressChannel) -> ChannelPolicy:
    return ChannelPolicy(
        channel,
        False,
        (),
        (),
        None,
        (),
        AuthorizationScopeKind.MACHINE,
        False,
        0,
        0,
        0,
    )


def _effective() -> EffectivePrivacyPolicy:
    policy = PrivacyPolicy(
        policy_id="pvy_10000000-0000-4000-8000-000000000004",
        version=1,
        policy_digest=_DIGEST,
        profile=PrivacyProfile.LOCAL_ONLY,
        review_context_profile=ReviewContextProfile.STRUCTURAL,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL),
        require_current_provider_data_use_evidence=False,
        network_egress_permitted=False,
        effective_scope=_scope(),
        channel_policies=tuple(
            _disabled(channel) for channel in sorted(EgressChannel, key=lambda c: c.value)
        ),
        local_model_enabled=False,
        local_model_binding=None,
        local_model_categories=(),
        local_model_data_classes=(),
        agent_context_categories=(DataCategory.FINDING_SUMMARY,),
        agent_context_data_classes=(DataClass.ORDINARY_USER_CONTENT, DataClass.PUBLIC_STRUCTURAL),
        trusted_human_control_categories=tuple(DataCategory),
        trusted_human_control_data_classes=(
            DataClass.ORDINARY_USER_CONTENT,
            DataClass.PUBLIC_STRUCTURAL,
        ),
        created_at=_NOW,
    )
    return EffectivePrivacyPolicy(policy, 1, _DIGEST)


def test_exact_scanner_reuses_shared_sensitive_content_detectors() -> None:
    kinds = scan_exact_bytes(b"api_key=sk-proj-abcdefghijklmnopqrstuvwxyz012345")
    assert kinds == (ForbiddenDataKind.API_CREDENTIAL,)


def test_exact_scanner_keeps_heuristics_separate_and_saturated_scans_fail_closed() -> None:
    heuristic = scan_exact_bytes_with_confidence(b"auth_token: 'bounded-but-suspicious-value'")
    assert heuristic.high_confidence == ()
    assert heuristic.heuristic == (ForbiddenDataKind.API_CREDENTIAL,)
    assert not heuristic.saturated

    concrete = scan_exact_bytes_with_confidence(
        b"GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456"
    )
    assert concrete.high_confidence == (ForbiddenDataKind.API_CREDENTIAL,)
    assert concrete.heuristic == ()

    saturated = scan_exact_bytes_with_confidence(b"\n".join([b"TOKEN=suspiciousvalue"] * 128))
    assert saturated.saturated
    assert saturated.high_confidence == (ForbiddenDataKind.API_CREDENTIAL,)


def test_source_denial_cannot_be_overridden_by_recipient_self_authorship() -> None:
    candidate = CandidateContext(
        request_id=_REQUEST,
        channel=None,
        local_sink=LocalDisclosureSink.AGENT_CONTEXT,
        purpose="client-result-projection",
        scope=_scope(),
        subject_digest=_DIGEST,
        provider_binding=None,
        items=(
            CandidateContextItem(
                "source-denied",
                DataCategory.FINDING_SUMMARY,
                _scope(),
                "/page/title",
                b"null",
                source_disclosure_permitted=False,
            ),
        ),
        provenance_context=_provenance_context(),
    )
    enforcer = LocalPrivacyEnforcer(
        provenance_resolver=_Provenance({"source-denied": DisclosureProvenance.SELF_AUTHORED})
    )
    classified = enforcer.classify(candidate, _effective())
    assert not classified.items[0].scope_valid
    decision = _decision(classified)
    assert decision.approved_item_ids == ()
    assert DataCategory.FINDING_SUMMARY in decision.blocked_categories


def test_classification_is_scope_bound_and_source_never_send_is_absolute() -> None:
    candidate = CandidateContext(
        request_id=_REQUEST,
        channel=None,
        local_sink=LocalDisclosureSink.LOCAL_HUMAN_VIEW,
        purpose="client-result-projection",
        scope=_scope(),
        subject_digest=_DIGEST,
        provider_binding=None,
        items=(
            CandidateContextItem(
                "public",
                DataCategory.BOUNDED_STRUCTURAL_METADATA,
                _scope(),
                "event:summary",
                b"three findings",
            ),
            CandidateContextItem(
                "secret",
                DataCategory.DIAGNOSTIC_METADATA,
                _scope(),
                "environment:raw",
                b"innocent-looking",
            ),
        ),
    )

    classified = LocalPrivacyEnforcer().classify(candidate, _effective())

    assert classified.items[0].data_class is DataClass.PUBLIC_STRUCTURAL
    assert classified.items[0].scope_valid
    assert classified.items[1].data_class is DataClass.SECRET_OR_CRYPTOGRAPHIC
    assert classified.items[1].forbidden_findings == (ForbiddenDataKind.UNRELATED_ENVIRONMENT,)


def test_minimization_is_deterministic_and_cannot_include_forbidden_item() -> None:
    candidate = CandidateContext(
        request_id=_REQUEST,
        channel=None,
        local_sink=LocalDisclosureSink.LOCAL_HUMAN_VIEW,
        purpose="client-result-projection",
        scope=_scope(),
        subject_digest=_DIGEST,
        provider_binding=None,
        items=(
            CandidateContextItem(
                "allowed",
                DataCategory.FINDING_SUMMARY,
                _scope(),
                "finding:one",
                b"bounded finding",
            ),
            CandidateContextItem(
                "forbidden",
                DataCategory.FINDING_SUMMARY,
                _scope(),
                "credential:file",
                b"not itself a token",
            ),
        ),
    )
    enforcer = LocalPrivacyEnforcer()
    classified = enforcer.classify(candidate, _effective())
    decision = PrivacyDecision(
        ("allowed", "forbidden"),
        (),
        PrivacyOutcome.COMPLETED,
        None,
    )

    first = enforcer.minimize_and_scan(classified, decision)
    second = enforcer.minimize_and_scan(classified, decision)

    assert first == second
    assert first.included_item_ids == ("allowed",)
    assert b"not itself a token" not in first.prepared_bytes
    assert first.forbidden_findings == ()


def test_heuristic_only_item_is_span_redacted_without_blocking_clean_item() -> None:
    candidate = CandidateContext(
        request_id=_REQUEST,
        channel=None,
        local_sink=LocalDisclosureSink.LOCAL_HUMAN_VIEW,
        purpose="privacy-test",
        scope=_scope(),
        subject_digest=_DIGEST,
        provider_binding=None,
        items=(
            CandidateContextItem(
                "clean",
                DataCategory.FINDING_SUMMARY,
                _scope(),
                "finding:clean",
                b"bounded finding",
            ),
            CandidateContextItem(
                "heuristic",
                DataCategory.EVIDENCE_EXCERPT,
                _scope(),
                "finding:heuristic",
                b"auth_token: 'bounded-but-suspicious-value'",
            ),
        ),
    )
    enforcer = LocalPrivacyEnforcer()
    classified = enforcer.classify(candidate, _effective())
    assert classified.items[0].heuristic_findings == ()
    assert classified.items[1].forbidden_findings == ()
    assert classified.items[1].heuristic_findings == (ForbiddenDataKind.API_CREDENTIAL,)
    assert _heuristic_only_item_ids(classified) == ("heuristic",)

    decision = _decision(classified)
    minimized = enforcer.minimize_and_scan(classified, decision)
    assert minimized.included_item_ids == ("clean", "heuristic")
    assert minimized.heuristic_item_ids == ()
    assert minimized.forbidden_findings == ()
    assert minimized.heuristic_findings == ()
    assert minimized.redacted_span_count == 1
    assert b"bounded-but-suspicious-value" not in minimized.prepared_bytes
    assert (
        base64.b64encode(b"auth_token: '[withheld-by-finishup:possible-credential]'")
        in minimized.prepared_bytes
    )


def test_mixed_case_keeps_concrete_credentials_as_whole_case_findings() -> None:
    candidate = CandidateContext(
        request_id=_REQUEST,
        channel=None,
        local_sink=LocalDisclosureSink.LOCAL_HUMAN_VIEW,
        purpose="semantic-review",
        scope=_scope(),
        subject_digest=_DIGEST,
        provider_binding=None,
        items=(
            CandidateContextItem(
                "clean",
                DataCategory.FINDING_SUMMARY,
                _scope(),
                "finding:clean",
                b"bounded finding",
            ),
            CandidateContextItem(
                "heuristic",
                DataCategory.FINDING_SUMMARY,
                _scope(),
                "finding:heuristic",
                b"TOKEN=opaque.value",
            ),
            CandidateContextItem(
                "credential",
                DataCategory.FINDING_SUMMARY,
                _scope(),
                "finding:credential",
                b"GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456",
            ),
        ),
    )
    enforcer = LocalPrivacyEnforcer()
    classified = enforcer.classify(candidate, _effective())
    decision = _decision(classified)

    assert classified.items[1].heuristic_findings == (ForbiddenDataKind.API_CREDENTIAL,)
    assert classified.items[2].forbidden_findings == (ForbiddenDataKind.API_CREDENTIAL,)
    assert decision.outcome is PrivacyOutcome.BLOCKED_FORBIDDEN_DATA
    assert decision.reason is PrivacyReason.NEVER_SEND_DETECTED


def test_semantic_heuristic_omission_keeps_review_packet_reference_closure() -> None:
    from finishup.protocol.canonical import strict_json_parse

    clean_ref = "evd_10000000-0000-4000-8000-000000000010"
    withheld_ref = "evd_10000000-0000-4000-8000-000000000011"
    envelope = canonical_encode(
        {
            "case_digest": _DIGEST,
            "case_id": "cas_10000000-0000-4000-8000-000000000012",
            "dependency_digest": _DIGEST,
            "frontier_refs": [clean_ref, withheld_ref],
            "local_check_refs": [],
            "item_catalog": [
                {
                    "category": "bounded_structural_metadata",
                    "item_id": "review-packet",
                    "section": "timeline",
                    "source_kind": "task",
                    "source_ref": "evt_10000000-0000-4000-8000-000000000013",
                    "linked_subject_refs": [],
                    "occurred_order": 0,
                },
                {
                    "category": "evidence_excerpt",
                    "item_id": "clean",
                    "section": "excerpt",
                    "source_kind": "evidence",
                    "source_ref": clean_ref,
                    "linked_subject_refs": [],
                    "occurred_order": 1,
                },
                {
                    "category": "evidence_excerpt",
                    "item_id": "heuristic",
                    "section": "excerpt",
                    "source_kind": "evidence",
                    "source_ref": withheld_ref,
                    "linked_subject_refs": [],
                    "occurred_order": 2,
                },
            ],
            "question_set": ["auth_token: envelope-suspicious-value"],
            "review_packet": {
                "targeted_excerpts": [
                    {"excerpt_item_id": "clean", "source_kind": "evidence"},
                    {"excerpt_item_id": "heuristic", "source_kind": "evidence"},
                ],
                "omissions": [],
            },
            "schema": "yoetz.review-packet-case/2",
        }
    )
    candidate = CandidateContext(
        request_id=_REQUEST,
        channel=EgressChannel.LLM_INFERENCE,
        local_sink=None,
        purpose="semantic-review",
        scope=_scope(),
        subject_digest=_DIGEST,
        provider_binding=None,
        items=(
            CandidateContextItem(
                "review-packet",
                DataCategory.BOUNDED_STRUCTURAL_METADATA,
                _scope(),
                "/case/review-packet",
                envelope,
            ),
            CandidateContextItem(
                "clean",
                DataCategory.EVIDENCE_EXCERPT,
                _scope(),
                "/case/excerpt/clean",
                b"clean evidence",
            ),
            CandidateContextItem(
                "heuristic",
                DataCategory.EVIDENCE_EXCERPT,
                _scope(),
                "/case/excerpt/heuristic",
                b'{"event_id":"evt_10000000-0000-4000-8000-000000000011",'
                b'"payload":{"auth_token":"bounded secret words"}}',
            ),
        ),
    )
    enforcer = LocalPrivacyEnforcer()
    classified = enforcer.classify(candidate, _effective())
    minimized = enforcer.minimize_and_scan(
        classified,
        PrivacyDecision(
            ("clean", "heuristic", "review-packet"),
            (),
            PrivacyOutcome.COMPLETED,
            None,
        ),
    )
    packet = strict_json_parse(minimized.prepared_bytes)
    assert isinstance(packet, dict)
    rows = packet["items"]
    assert isinstance(rows, list)
    source_refs: list[str] = []
    for row in rows:
        if isinstance(row, dict):
            source_ref = row.get("source_ref")
            if type(source_ref) is str:
                source_refs.append(source_ref)
    assert set(source_refs) == {clean_ref, withheld_ref}
    review_packet = packet["review_packet"]
    assert isinstance(review_packet, dict)
    omissions = review_packet["omissions"]
    assert isinstance(omissions, list)
    assert not any(
        isinstance(row, dict) and row.get("subject_ref") == withheld_ref for row in omissions
    )
    targeted = review_packet["targeted_excerpts"]
    assert isinstance(targeted, list)
    targeted_ids: list[str] = []
    for row in targeted:
        if isinstance(row, dict) and type(item_id := row.get("excerpt_item_id")) is str:
            targeted_ids.append(item_id)
    assert set(targeted_ids) == {"clean", "heuristic"}
    redacted_targeted = [
        row
        for row in targeted
        if isinstance(row, dict) and row.get("excerpt_item_id") == "heuristic"
    ]
    assert redacted_targeted[0].get("content_visibility") == "redacted_never_send"
    assert b"bounded secret words" not in minimized.prepared_bytes
    assert minimized.heuristic_findings == ()
    heuristic_rows = [
        row for row in rows if isinstance(row, dict) and row.get("item_id") == "heuristic"
    ]
    assert len(heuristic_rows) == 1
    content = heuristic_rows[0].get("content")
    assert type(content) is str
    assert json.loads(content) == {
        "event_id": "evt_10000000-0000-4000-8000-000000000011",
        "payload": {"auth_token": "[withheld-by-finishup:possible-credential]"},
    }
    assert packet["question_set"] == ["auth_token: [withheld-by-finishup:possible-credential]"]


def test_malformed_semantic_envelope_cannot_dispatch_empty_fallback() -> None:
    candidate = CandidateContext(
        request_id=_REQUEST,
        channel=EgressChannel.LLM_INFERENCE,
        local_sink=None,
        purpose="semantic-review",
        scope=_scope(),
        subject_digest=_DIGEST,
        provider_binding=None,
        items=(
            CandidateContextItem(
                "review-packet",
                DataCategory.BOUNDED_STRUCTURAL_METADATA,
                _scope(),
                "/case/review-packet",
                b"not a review packet",
            ),
            CandidateContextItem(
                "clean",
                DataCategory.FINDING_SUMMARY,
                _scope(),
                "/case/summary",
                b"bounded finding",
            ),
        ),
    )
    enforcer = LocalPrivacyEnforcer()
    classified = enforcer.classify(candidate, _effective())
    minimized = enforcer.minimize_and_scan(
        classified,
        PrivacyDecision(
            ("clean", "review-packet"),
            (),
            PrivacyOutcome.COMPLETED,
            None,
        ),
    )

    assert minimized.included_item_ids == ()
    assert json.loads(minimized.prepared_bytes) == {
        "items": [],
        "omissions": [],
        "schema": "yoetz.review-packet-case/2",
    }


def test_non_targeted_redaction_is_bound_in_provider_manifest() -> None:
    from finishup.application.semantic_case import (
        assemble_filtered_review_packet,
        review_packet_disclosure_result,
    )
    from finishup.protocol.canonical import strict_json_parse

    source_ref = "evd_10000000-0000-4000-8000-000000000014"

    def section(*, item_ids: list[str], source_refs: list[str]) -> dict[str, object]:
        return {
            "content_bytes": 1,
            "content_digest": _DIGEST,
            "item_ids": item_ids,
            "omission_reasons": [],
            "omitted_refs": [],
            "revision": 1,
            "source_refs": source_refs,
            "status": "complete",
        }

    envelope: dict[str, object] = {
        "case_digest": _DIGEST,
        "case_id": "cas_10000000-0000-4000-8000-000000000015",
        "dependency_digest": _DIGEST,
        "frontier_refs": [source_ref],
        "item_catalog": [
            {
                "category": "evidence_excerpt",
                "content_bytes": 25,
                "item_id": "redacted",
                "section": "excerpt",
                "source_kind": "evidence",
                "source_ref": source_ref,
                "linked_subject_refs": [source_ref],
                "occurred_order": 0,
            }
        ],
        "local_check_refs": [],
        "review_packet": {
            "review_input_manifest": {
                "caller_evidence": section(item_ids=["redacted"], source_refs=[source_ref]),
                "current_diff": section(item_ids=[], source_refs=[]),
                "latest_verification": section(item_ids=[], source_refs=[]),
                "missing_inputs": [],
                "omitted_item_count": 0,
                "phase": "composed",
                "prior_finding_context": section(item_ids=[], source_refs=[]),
                "schema": "yoetz.review-input-manifest/1",
                "selected_excerpt_bytes": 25,
                "selected_item_count": 1,
                "specification": section(item_ids=[], source_refs=[]),
            },
            "targeted_excerpts": [],
            "omissions": [],
        },
        "schema": "yoetz.review-packet-case/2",
    }
    prepared = assemble_filtered_review_packet(
        envelope,
        content_by_id={"redacted": b'auth_token: "[REDACTED]"'},
        included_item_ids={"redacted"},
        redacted_item_ids={"redacted"},
    )
    packet = strict_json_parse(prepared)
    assert isinstance(packet, dict)
    rows = packet["items"]
    assert isinstance(rows, list)
    assert isinstance(rows[0], dict)
    assert rows[0]["transformations"] == [
        {
            "after_bytes": 24,
            "before_bytes": 25,
            "kind": "redacted",
            "reason": "sensitive_redacted",
        }
    ]
    result = review_packet_disclosure_result(prepared)
    assert result.failure is None
    assert result.disclosure is not None
    assert result.disclosure.provider_input_manifest is not None


class _Provenance:
    def __init__(self, facts: dict[str, DisclosureProvenance | None]) -> None:
        self._facts = facts

    def resolve(
        self,
        context: ProjectionProvenanceContext,
        candidate: CandidateContext,
        item: CandidateContextItem,
    ) -> DisclosureProvenance | None:
        assert context == _provenance_context()
        del candidate
        return self._facts[item.item_id]


def _provenance_context() -> ProjectionProvenanceContext:
    return ProjectionProvenanceContext(_SESSION, _WRITER, _FRONTIER)


def _decision(classified: ClassifiedContext) -> PrivacyDecision:
    coordinator = object.__new__(PrivacyCoordinator)
    return coordinator._local_decision(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
        classified, _effective()
    )


def test_local_human_view_is_not_category_or_data_class_gated() -> None:
    candidate = CandidateContext(
        request_id=_REQUEST,
        channel=None,
        local_sink=LocalDisclosureSink.LOCAL_HUMAN_VIEW,
        purpose="client-result-projection",
        scope=_scope(),
        subject_digest=_DIGEST,
        provider_binding=None,
        items=(
            CandidateContextItem(
                "human-visible",
                DataCategory.REPOSITORY_EXCERPT,
                _scope(),
                "result:detail",
                b"private project detail",
            ),
        ),
    )
    classified = LocalPrivacyEnforcer().classify(candidate, _effective())

    decision = _decision(classified)

    assert decision.outcome is PrivacyOutcome.COMPLETED
    assert decision.approved_item_ids == ("human-visible",)


def test_agent_context_uses_trusted_provenance_and_ambiguity_denies_widening() -> None:
    candidate = CandidateContext(
        request_id=_REQUEST,
        channel=None,
        local_sink=LocalDisclosureSink.AGENT_CONTEXT,
        purpose="client-result-projection",
        scope=_scope(),
        subject_digest=_DIGEST,
        provider_binding=None,
        items=(
            CandidateContextItem(
                "self-authored",
                DataCategory.TASK_DESCRIPTION,
                _scope(),
                "event:self",
                b"the agent's own text",
            ),
            CandidateContextItem(
                "ambiguous",
                DataCategory.REPOSITORY_EXCERPT,
                _scope(),
                "result:unknown",
                b"unknown authorship",
            ),
            CandidateContextItem(
                "granted-other",
                DataCategory.FINDING_SUMMARY,
                _scope(),
                "finding:other",
                b"other writer finding",
            ),
        ),
        provenance_context=_provenance_context(),
    )
    resolver = _Provenance(
        {
            "self-authored": DisclosureProvenance.SELF_AUTHORED,
            "ambiguous": None,
            "granted-other": DisclosureProvenance.OTHER_WRITER,
        }
    )
    classified = LocalPrivacyEnforcer(provenance_resolver=resolver).classify(
        candidate, _effective()
    )

    decision = _decision(classified)

    assert decision.outcome is PrivacyOutcome.COMPLETED
    assert decision.approved_item_ids == ("granted-other", "self-authored")
    assert DataCategory.REPOSITORY_EXCERPT in decision.blocked_categories


def test_agent_self_authorship_never_widens_sensitive_data_class() -> None:
    candidate = CandidateContext(
        request_id=_REQUEST,
        channel=None,
        local_sink=LocalDisclosureSink.AGENT_CONTEXT,
        purpose="client-result-projection",
        scope=_scope(),
        subject_digest=_DIGEST,
        provider_binding=None,
        items=(
            CandidateContextItem(
                "sensitive-self",
                DataCategory.TASK_DESCRIPTION,
                _scope(),
                "event:self",
                b"sensitive value",
            ),
        ),
        provenance_context=_provenance_context(),
    )
    classified = LocalPrivacyEnforcer(
        provenance_resolver=_Provenance({"sensitive-self": DisclosureProvenance.SELF_AUTHORED})
    ).classify(candidate, _effective())
    sensitive = ClassifiedContext(
        classified.candidate,
        (replace(classified.items[0], data_class=DataClass.SENSITIVE_CONFIDENTIAL),),
    )

    decision = _decision(sensitive)

    assert decision.outcome is PrivacyOutcome.BLOCKED_BY_POLICY
    assert decision.approved_item_ids == ()


def test_missing_agent_provenance_context_is_ambiguous_and_grants_no_widening() -> None:
    candidate = CandidateContext(
        request_id=_REQUEST,
        channel=None,
        local_sink=LocalDisclosureSink.AGENT_CONTEXT,
        purpose="client-result-projection",
        scope=_scope(),
        subject_digest=_DIGEST,
        provider_binding=None,
        items=(
            CandidateContextItem(
                "ambiguous",
                DataCategory.REPOSITORY_EXCERPT,
                _scope(),
                "result:unknown",
                b"unknown authorship",
            ),
        ),
    )
    classified = LocalPrivacyEnforcer().classify(candidate, _effective())

    decision = _decision(classified)

    assert decision.outcome is PrivacyOutcome.BLOCKED_BY_POLICY
    assert decision.approved_item_ids == ()


def test_provenance_context_is_forbidden_for_non_agent_sink() -> None:
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        CandidateContext(
            request_id=_REQUEST,
            channel=None,
            local_sink=LocalDisclosureSink.LOCAL_HUMAN_VIEW,
            purpose="client-result-projection",
            scope=_scope(),
            subject_digest=_DIGEST,
            provider_binding=None,
            items=(),
            provenance_context=_provenance_context(),
        )


def test_cross_task_item_denies_agent_provenance_widening() -> None:
    other_scope = AuthorizationScope(
        AuthorizationScopeKind.TASK,
        _INSTALLATION,
        _WORKSPACE,
        _OTHER_TASK,
    )
    candidate = CandidateContext(
        request_id=_REQUEST,
        channel=None,
        local_sink=LocalDisclosureSink.AGENT_CONTEXT,
        purpose="client-result-projection",
        scope=_scope(),
        subject_digest=_DIGEST,
        provider_binding=None,
        items=(
            CandidateContextItem(
                "cross-task",
                DataCategory.TASK_DESCRIPTION,
                other_scope,
                "event:other-task",
                b"text outside the projection task",
            ),
        ),
        provenance_context=_provenance_context(),
    )
    classified = LocalPrivacyEnforcer(
        provenance_resolver=_Provenance({"cross-task": DisclosureProvenance.SELF_AUTHORED})
    ).classify(candidate, _effective())

    decision = _decision(classified)

    assert decision.outcome is PrivacyOutcome.CLASSIFICATION_UNCERTAIN
    assert decision.approved_item_ids == ()


def test_candidate_origin_accepts_bounded_canonical_json_pointer() -> None:
    item = CandidateContextItem(
        "pointer-item",
        DataCategory.FINDING_SUMMARY,
        _scope(),
        "/findings/0/detail~1text",
        b"detail",
    )

    assert item.origin_ref == "/findings/0/detail~1text"


def test_empty_local_projection_is_an_approved_structural_decision() -> None:
    candidate = CandidateContext(
        request_id=_REQUEST,
        channel=None,
        local_sink=LocalDisclosureSink.AGENT_CONTEXT,
        purpose="client-result-projection",
        scope=_scope(),
        subject_digest=_DIGEST,
        provider_binding=None,
        items=(),
        provenance_context=_provenance_context(),
    )
    classified = LocalPrivacyEnforcer().classify(candidate, _effective())

    decision = _decision(classified)

    assert decision == PrivacyDecision((), (), PrivacyOutcome.COMPLETED, None)


def _two_excerpt_semantic_candidate(clean: bytes, suspect: bytes) -> CandidateContext:
    clean_ref = "evd_10000000-0000-4000-8000-000000000020"
    suspect_ref = "evd_10000000-0000-4000-8000-000000000021"
    envelope = canonical_encode(
        {
            "case_digest": _DIGEST,
            "case_id": "cas_10000000-0000-4000-8000-000000000022",
            "dependency_digest": _DIGEST,
            "frontier_refs": [clean_ref, suspect_ref],
            "local_check_refs": [],
            "item_catalog": [
                {
                    "category": "bounded_structural_metadata",
                    "item_id": "review-packet",
                    "section": "timeline",
                    "source_kind": "task",
                    "source_ref": "evt_10000000-0000-4000-8000-000000000023",
                    "linked_subject_refs": [],
                    "occurred_order": 0,
                },
                {
                    "category": "evidence_excerpt",
                    "item_id": "clean",
                    "section": "excerpt",
                    "source_kind": "evidence",
                    "source_ref": clean_ref,
                    "linked_subject_refs": [],
                    "occurred_order": 1,
                },
                {
                    "category": "evidence_excerpt",
                    "item_id": "suspect",
                    "section": "excerpt",
                    "source_kind": "evidence",
                    "source_ref": suspect_ref,
                    "linked_subject_refs": [],
                    "occurred_order": 2,
                },
            ],
            "question_set": ["What did you verify?"],
            "review_packet": {
                "targeted_excerpts": [
                    {"excerpt_item_id": "clean", "source_kind": "evidence"},
                    {"excerpt_item_id": "suspect", "source_kind": "evidence"},
                ],
                "omissions": [],
            },
            "schema": "yoetz.review-packet-case/2",
        }
    )
    return CandidateContext(
        request_id=_REQUEST,
        channel=EgressChannel.LLM_INFERENCE,
        local_sink=None,
        purpose="semantic-review",
        scope=_scope(),
        subject_digest=_DIGEST,
        provider_binding=None,
        items=(
            CandidateContextItem(
                "review-packet",
                DataCategory.BOUNDED_STRUCTURAL_METADATA,
                _scope(),
                "/case/review-packet",
                envelope,
            ),
            CandidateContextItem(
                "clean", DataCategory.EVIDENCE_EXCERPT, _scope(), "/case/excerpt/clean", clean
            ),
            CandidateContextItem(
                "suspect",
                DataCategory.EVIDENCE_EXCERPT,
                _scope(),
                "/case/excerpt/suspect",
                suspect,
            ),
        ),
    )


def _no_op_redaction(
    data: bytes, *, marker_spans: tuple[tuple[int, int], ...] = ()
) -> tuple[bytes, int, tuple[tuple[int, int], ...]]:
    """Simulate a redaction that leaves a heuristic in the prepared bytes."""

    return data, 1, marker_spans


def _minimize_all(candidate: CandidateContext):  # noqa: ANN202 - test helper
    enforcer = LocalPrivacyEnforcer()
    classified = enforcer.classify(candidate, _effective())
    return enforcer.minimize_and_scan(
        classified,
        PrivacyDecision(("clean", "review-packet", "suspect"), (), PrivacyOutcome.COMPLETED, None),
    )


@pytest.mark.parametrize(
    "line",
    (
        b'        self.api_key = "Zx81Kq0Lm2Pq9Rs7"\n',
        b"    API_TOKEN=abcdefgh12345678\n",
    ),
)
def test_redacted_code_line_survives_packet_encoding_without_blocking(line: bytes) -> None:
    """TB4 tb4f1 regression (issue #976): the JSON-escaped marker no longer re-matches.

    batched-eval-parity and data-anonymization lost every implementation-stage review because a
    redacted line like ``self.token = [REDACTED]\\n`` re-matched once encoded into the packet.
    """

    minimized = _minimize_all(_two_excerpt_semantic_candidate(b"clean evidence", line))
    assert minimized.heuristic_findings == ()
    assert minimized.forbidden_findings == ()
    assert set(minimized.included_item_ids) == {"clean", "review-packet", "suspect"}
    assert minimized.withheld_item_ids == ()
    assert b"[withheld-by-finishup:possible-credential]" in minimized.prepared_bytes


def test_surviving_heuristic_withholds_only_the_offending_item(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Partial withholding (issue #976): one offending item is withheld, the rest is reviewed."""

    import finishup.adapters.privacy.local_enforcer as enforcer_module

    # Simulate a redaction that leaves a heuristic in the prepared bytes.
    monkeypatch.setattr(enforcer_module, "redact_heuristic_spans_marked", _no_op_redaction)
    minimized = _minimize_all(
        _two_excerpt_semantic_candidate(b"clean evidence", b"API_TOKEN=abcdefgh12345678\n")
    )
    assert minimized.heuristic_findings == ()
    assert minimized.forbidden_findings == ()
    assert set(minimized.included_item_ids) == {"clean", "review-packet"}
    assert minimized.withheld_item_ids == ("suspect",)
    assert b"abcdefgh12345678" not in minimized.prepared_bytes
    assert b"clean evidence" in minimized.prepared_bytes


def test_surviving_heuristic_redacts_only_the_value_in_place(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Owner decision B2 (issue #982): redact the value, not the item.

    When a heuristic survives the raw-text pass into the prepared packet, the offending item is
    re-redacted on its packet encoding and stays in the review; only the value is replaced, by the
    fixed placeholder that says it may be a credential. The rest of the item is still sent.
    """

    import finishup.adapters.privacy.local_enforcer as enforcer_module
    from finishup.observability.privacy import EGRESS_CREDENTIAL_PLACEHOLDER

    real = enforcer_module.redact_heuristic_spans_marked
    calls = {"count": 0}

    def first_pass_misses(
        data: bytes, *, marker_spans: tuple[tuple[int, int], ...] = ()
    ) -> tuple[bytes, int, tuple[tuple[int, int], ...]]:
        calls["count"] += 1
        return (
            (data, 0, marker_spans)
            if calls["count"] == 1
            else real(data, marker_spans=marker_spans)
        )

    monkeypatch.setattr(enforcer_module, "redact_heuristic_spans_marked", first_pass_misses)
    minimized = _minimize_all(
        _two_excerpt_semantic_candidate(
            b"clean evidence",
            b"def connect():\n    API_TOKEN=abcdefgh12345678\n    return open_session()\n",
        )
    )
    assert minimized.heuristic_findings == ()
    assert minimized.forbidden_findings == ()
    assert set(minimized.included_item_ids) == {"clean", "review-packet", "suspect"}
    assert minimized.withheld_item_ids == ()
    assert minimized.redacted_span_count >= 1
    assert b"abcdefgh12345678" not in minimized.prepared_bytes
    assert EGRESS_CREDENTIAL_PLACEHOLDER in minimized.prepared_bytes
    assert b"return open_session()" in minimized.prepared_bytes
    assert b"clean evidence" in minimized.prepared_bytes


def test_heuristic_in_structural_envelope_still_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.adapters.privacy.local_enforcer as enforcer_module

    monkeypatch.setattr(enforcer_module, "redact_heuristic_spans_marked", _no_op_redaction)
    candidate = _two_excerpt_semantic_candidate(b"clean evidence", b"plain words")
    envelope = candidate.items[0]
    poisoned = replace(
        envelope,
        plaintext=envelope.plaintext.replace(
            b"What did you verify?", b"auth_token: envelope-suspicious-value"
        ),
    )
    minimized = _minimize_all(replace(candidate, items=(poisoned, *candidate.items[1:])))
    assert minimized.heuristic_findings


_SUSPECT_REF = "evd_10000000-0000-4000-8000-000000000021"


def test_raw_pass_reports_replaced_value_lines_and_ref_never_the_value() -> None:
    """PL2-1 (issue #982): item ref plus 1-based lines in the item's own text, never the value."""

    from finishup.protocol.redacted_values import SemanticRedactedValue

    minimized = _minimize_all(
        _two_excerpt_semantic_candidate(
            b"clean evidence",
            b"def connect():\n    pass\n    API_TOKEN=abcdefgh12345678\n"
            b'    password = "hunter2-long-value"\n',
        )
    )
    assert minimized.withheld_item_ids == ()
    assert minimized.redacted_values == (
        SemanticRedactedValue("suspect", "value_replaced", (3, 4), _SUSPECT_REF),
    )
    rendered = repr(minimized.redacted_values).encode()
    assert b"abcdefgh12345678" not in rendered
    assert b"hunter2" not in rendered


def test_encoded_pass_reports_replaced_value_lines(monkeypatch: pytest.MonkeyPatch) -> None:
    import finishup.adapters.privacy.local_enforcer as enforcer_module
    from finishup.protocol.redacted_values import SemanticRedactedValue

    real = enforcer_module.redact_heuristic_spans_marked
    calls = {"count": 0}

    def first_pass_misses(
        data: bytes, *, marker_spans: tuple[tuple[int, int], ...] = ()
    ) -> tuple[bytes, int, tuple[tuple[int, int], ...]]:
        calls["count"] += 1
        return (
            (data, 0, marker_spans)
            if calls["count"] == 1
            else real(data, marker_spans=marker_spans)
        )

    monkeypatch.setattr(enforcer_module, "redact_heuristic_spans_marked", first_pass_misses)
    minimized = _minimize_all(
        _two_excerpt_semantic_candidate(
            b"clean evidence",
            b"def connect():\n    API_TOKEN=abcdefgh12345678\n    return open_session()\n",
        )
    )
    assert minimized.withheld_item_ids == ()
    assert minimized.redacted_values == (
        SemanticRedactedValue("suspect", "value_replaced", (2,), _SUSPECT_REF),
    )
    assert b"abcdefgh12345678" not in repr(minimized.redacted_values).encode()


def test_withheld_item_reports_its_ref_and_matched_lines(monkeypatch: pytest.MonkeyPatch) -> None:
    import finishup.adapters.privacy.local_enforcer as enforcer_module
    from finishup.protocol.redacted_values import SemanticRedactedValue

    monkeypatch.setattr(enforcer_module, "redact_heuristic_spans_marked", _no_op_redaction)
    minimized = _minimize_all(
        _two_excerpt_semantic_candidate(
            b"clean evidence", b"first line\nsecond line\nAPI_TOKEN=abcdefgh12345678\n"
        )
    )
    assert minimized.withheld_item_ids == ("suspect",)
    assert minimized.redacted_values == (
        SemanticRedactedValue("suspect", "item_withheld", (3,), _SUSPECT_REF),
    )


def test_clean_case_reports_no_redacted_values() -> None:
    minimized = _minimize_all(_two_excerpt_semantic_candidate(b"clean evidence", b"plain words"))
    assert minimized.redacted_values == ()


def test_heuristic_value_lines_reads_raw_and_json_string_forms() -> None:
    from finishup.observability.privacy import heuristic_value_lines

    text = 'first\nAPI_KEY=abcdefgh1234zz\nok\n  password: "hunter2-long-value"\n'
    assert heuristic_value_lines(text.encode()) == (2, 4)
    # In the encoded form the escaped newline hides the first assignment's boundary, so only
    # the later value is found; its line is still counted in the decoded text.
    assert heuristic_value_lines(canonical_encode(text), json_string=True) == (4,)
    assert heuristic_value_lines(b"plain words") == ()
    many = b"".join(b"API_TOKEN=abcdefgh%08d\n" % index for index in range(40))
    assert heuristic_value_lines(many) == tuple(range(1, 33))


def _size_check_line() -> int:
    """The line of ``MinimizedDisclosure``'s ``raise`` for a prepared payload over the cap."""

    import inspect

    import finishup.ports.privacy as privacy_module

    lines, start = inspect.getsourcelines(privacy_module.MinimizedDisclosure.__post_init__)
    check = next(i for i, text in enumerate(lines) if "> MAX_MINIMIZED_DISCLOSURE_BYTES" in text)
    raised = next(i for i in range(check, len(lines)) if "raise _invalid()" in lines[i])
    return start + raised


def _rendered(minimized: MinimizedDisclosure, payload: bytes) -> MinimizedDisclosure:
    """What egress does with an approved packet placed in a reviewer exchange (#1118)."""

    return replace(minimized, prepared_bytes=payload, byte_count=len(payload))


@pytest.mark.parametrize(
    ("clean", "suspect", "redact"),
    (
        # The same file captured twice: identical bytes under two case items.
        (b"def add(a, b):\n    return a + b\n", b"def add(a, b):\n    return a + b\n", False),
        # A value replaced in place and reported by line.
        (b"clean evidence", b'        self.api_key = "Zx81Kq0Lm2Pq9Rs7"\n', False),
        # An item withheld because its value could not be redacted.
        (b"clean evidence", b"API_TOKEN=abcdefgh12345678\n", True),
    ),
)
def test_a_reviewer_exchange_can_only_fail_the_disclosure_on_its_size(
    monkeypatch: pytest.MonkeyPatch, clean: bytes, suspect: bytes, redact: bool
) -> None:
    """#1118 smoke: four reviews ended ``coordinator_failure`` at ``finishup.ports.privacy:529``.

    Placing the packet in the reviewer exchange changes only the prepared bytes, their count,
    token estimate and digest; repeated captures, redacted values and withheld items were already
    validated by the same constructor. Within the cap every such disclosure is valid; one byte
    over it fails the size check, and that check is the one ``exception_origin`` names.
    """

    import finishup.adapters.privacy.local_enforcer as enforcer_module
    from finishup.application.reviewer_run import reviewer_first_exchange
    from finishup.observability.logging import exception_origin
    from finishup.ports.privacy import MAX_MINIMIZED_DISCLOSURE_BYTES

    if redact:
        monkeypatch.setattr(enforcer_module, "redact_heuristic_spans_marked", _no_op_redaction)
    minimized = _minimize_all(_two_excerpt_semantic_candidate(clean, suspect))
    if clean == suspect:
        assert len(minimized.source_item_digests) == 2  # the packet envelope and one source
    elif redact:
        assert minimized.withheld_item_ids == ("suspect",) and minimized.redacted_values
    else:
        assert minimized.redacted_span_count and minimized.redacted_values
    exchange = reviewer_first_exchange(minimized.prepared_bytes, '{"reviewer_catalog":{}}')
    assert _rendered(minimized, exchange).byte_count == len(exchange)
    assert _rendered(minimized, b"x" * MAX_MINIMIZED_DISCLOSURE_BYTES).byte_count > 0
    with pytest.raises(ValueError, match="invalid_privacy_port_value") as raised:
        _rendered(minimized, b"x" * (MAX_MINIMIZED_DISCLOSURE_BYTES + 1))
    assert exception_origin(raised.value) == f"finishup.ports.privacy:{_size_check_line()}"
