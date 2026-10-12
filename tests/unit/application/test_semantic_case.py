"""Frozen privacy-selected AI-powered review case construction (plan 03 / issue #69)."""

from __future__ import annotations

import hashlib
import inspect
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from typing import cast

import pytest

from builders.policy_cases import (
    act,
    claim_record,
    clm,
    evd,
    evidence_record,
    make_case,
    obl,
    obligation_record,
    plan_record,
    record,
    res,
)
from builders.replay import replay_records
from yoetz.application import semantic_case as semantic_case_module
from yoetz.application.check import (
    CheckScope,
    allocate_findings,
    prior_finding_ids,
    run_deterministic_policies,
)
from yoetz.application.semantic_case import (
    OVER_CASE_ITEM_LIMIT_REASON,
    REVIEW_PACKET_ITEM_ID,
    REVIEW_PHASE_QUESTIONS,
    CapturedContentScope,
    CapturedSemanticContent,
    bounded_case_envelope,
    build_semantic_case,
    review_packet_disclosure_result,
    review_question_set,
    review_selection_digest,
    semantic_case_to_candidate_context,
    semantic_case_to_prepared_payload,
)
from yoetz.domain.events import (
    MAX_TEXT_BYTES,
    ActionKind,
    ActionRecordedPayload,
    ClaimKind,
    ClaimRecordedPayload,
    ClaimRecordedPayloadV1_1,
    EvidenceContentAvailability,
    EvidenceDigestBinding,
    EvidenceDigestProvenance,
    EvidenceDigestSubject,
    EvidenceKind,
    EvidenceRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    ResultOutcome,
    ResultRecordedPayload,
)
from yoetz.domain.findings import Finding
from yoetz.domain.observation import ObservationContentKind, ObservationContentManifest
from yoetz.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    ProviderBinding,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from yoetz.domain.receipts import SEMANTIC_CASE_CONTENT_OVER_ITEM_LIMIT_GAP
from yoetz.domain.values import EvidenceId, object_id, timestamp_from_string
from yoetz.kernel.deterministic_checks import (
    CaseAvailabilityFacts,
    DeterministicCase,
    build_deterministic_case,
)
from yoetz.kernel.projections import EvidenceProjectionRecord
from yoetz.kernel.reducers import replay
from yoetz.ports.objects import ObjectKind, ObjectMetadata, ObjectRef
from yoetz.ports.semantic import ExcerptDigestProvenance, SemanticCase
from yoetz.ports.semantic_budget import SemanticBudgetProfile, select_semantic_budget_profile
from yoetz.protocol.canonical import JsonValue, strict_json_parse
from yoetz.protocol.coverage import EvidenceImmutability, LedgerFreshness
from yoetz.protocol.ids import IdKind, new_id
from yoetz.protocol.models import MAX_REVIEW_TEXT_BYTES, DataCategory


class _Ids:
    def new(self, kind: IdKind) -> str:
        return new_id(kind)


def _case_with_material(*, with_evidence: bool = True) -> DeterministicCase:
    plan = plan_record(PlanPublishedPayload(1, "Ship the review packet", (obl(1),)), 1)
    obligation = obligation_record(
        ObligationPublishedPayload(
            obl(1), "Build the real packet", "tests pass", ObligationStatus.OPEN
        ),
        2,
    )
    supports = (evd(1),) if with_evidence else ()
    claim = record(
        ClaimRecordedPayload(
            clm(1),
            ClaimKind.COMPLETION,
            "Work is complete",
            supports,
            obligation_refs=(obl(1),),
        ),
        3,
    )
    evidence: dict[EvidenceId, EvidenceProjectionRecord] = {}
    extra = (clm(1), obl(1))
    if with_evidence:
        evidence[evd(1)] = evidence_record(
            EvidenceRecordedPayload(
                evd(1),
                EvidenceKind.TEST_RESULT,
                EvidenceImmutability.METADATA_ONLY,
                timestamp_from_string("2026-07-01T00:00:00.000Z"),
                description="test output: 1 failed assertion",
            ),
            4,
        )
        extra = (*extra, evd(1))
    return make_case(
        plans={1: plan},
        obligations={obl(1): obligation},
        claims={clm(1): claim},
        evidence=evidence,
        extra_refs=extra,
    )


def _findings_for(case: DeterministicCase) -> tuple[Finding, ...]:
    assessments, _ = run_deterministic_policies(
        case,
        CheckScope((), ()),
        ("research-evidence/0.2.0", "work-integrity/0.3.0"),
    )
    return allocate_findings(
        _Ids(),
        tuple(item.candidate for item in assessments),
        prior_finding_ids(case.projection),
    )


def _build(
    case: DeterministicCase,
    profile: ReviewContextProfile,
    *,
    findings: Sequence[Finding] = (),
    dependency: str = "sha256:" + "b" * 64,
    captured_content: Sequence[CapturedSemanticContent] = (),
    captured_content_scope: CapturedContentScope | None = None,
    captured_content_gaps: Sequence[str] = (),
    selection: ReviewSelectionPolicy | None = None,
) -> SemanticCase:
    return build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=case,
        dependency_digest=dependency,
        findings=findings,
        review_context_profile=profile,
        review_selection=selection or ReviewSelectionPolicy.for_profile(profile),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        captured_content=captured_content,
        captured_content_scope=captured_content_scope,
        captured_content_gaps=captured_content_gaps,
    )


def _captured_case_values(
    content: bytes = b"planted-defect-marker: missing validation",
    *,
    redacted: bool = False,
    phase_identity: str = "sha256:" + "4" * 64,
) -> tuple[DeterministicCase, CapturedSemanticContent, CapturedContentScope]:
    base = _case_with_material(with_evidence=True)
    object_value = object_id("obj_00000000-0000-4000-8000-000000000302")
    content_digest = "sha256:" + hashlib.sha256(content).hexdigest()
    payload = EvidenceRecordedPayload(
        evidence_id=evd(1),
        evidence_kind=EvidenceKind.OTHER,
        strength=EvidenceImmutability.IMMUTABLE_SNAPSHOT,
        observed_at=timestamp_from_string("2026-07-01T00:00:00.000Z"),
        captured_object_id=object_value,
        content_digest=content_digest,
        description="Observation-captured tool output bytes part=1/1",
        digest_binding=EvidenceDigestBinding(
            subject=EvidenceDigestSubject.BOUNDED_EXCERPT,
            content_availability=EvidenceContentAvailability.CAPTURED,
            byte_count=len(content),
            provenance=EvidenceDigestProvenance.OBSERVATION_CAPTURED,
        ),
    )
    observed = make_case(
        plans=base.projection.plans,
        obligations=base.projection.obligations,
        claims=base.projection.claims,
        evidence={evd(1): evidence_record(payload, 4)},
        extra_refs=(clm(1), obl(1), evd(1)),
    )
    envelope_digest = "sha256:" + "5" * 64
    object_ref = ObjectRef(
        object_id=object_value,
        plaintext_size=1_024,
        commitment="hmac-sha256:" + "6" * 64,
        envelope_digest=envelope_digest,
        encryption_format="yoetz-object/1",
        key_slot="task",
        metadata=ObjectMetadata(
            ObjectKind.CAPTURED_CONTENT,
            "application/vnd.yoetz.observation-content+json",
            "tsk_10000000-0000-4000-8000-000000000001",
            datetime(2026, 7, 1, tzinfo=UTC),
        ),
    )
    manifest = ObservationContentManifest(
        object_id=object_value,
        envelope_digest=envelope_digest,
        content_kind=ObservationContentKind.TOOL_OUTPUT,
        part_index=0,
        part_count=1,
        redacted=redacted,
        content_digest=content_digest,
        content_bytes=len(content),
        correlation_identity="tool-use-1",
        source_commitment="hmac-sha256:" + "7" * 64,
    )
    captured = CapturedSemanticContent(
        object_ref=object_ref,
        manifest=manifest,
        content=content,
        task_id="tsk_10000000-0000-4000-8000-000000000001",
        session_id="ses_10000000-0000-4000-8000-000000000001",
        workspace_commitment="hmac-sha256:" + "8" * 64,
        phase_identity=phase_identity,
        capture_profile="claude-code-ordinary-observation-v1",
        capture_gaps=("content_redacted",) if redacted else (),
    )
    scope = CapturedContentScope(
        task_id=captured.task_id,
        session_id=captured.session_id,
        workspace_commitment=captured.workspace_commitment,
        authorized_profiles=("claude-code-ordinary-observation-v1",),
        phase_bindings=((str(evd(1)), phase_identity),),
    )
    return observed, captured, scope


def _opaque_before_capture_case() -> tuple[
    DeterministicCase, CapturedSemanticContent, CapturedContentScope, EvidenceId
]:
    """Build a case where metadata-only evidence sorts before authenticated capture."""

    base, captured, scope = _captured_case_values(b"captured-selection-marker")
    opaque: dict[EvidenceId, EvidenceProjectionRecord] = {}
    for index in range(1, 17):
        ref = evd(index)
        opaque[ref] = evidence_record(
            EvidenceRecordedPayload(
                evidence_id=ref,
                evidence_kind=EvidenceKind.OTHER,
                strength=EvidenceImmutability.METADATA_ONLY,
                observed_at=timestamp_from_string("2026-07-01T00:00:00.000Z"),
                description="Opaque observation kind=event_msg",
            ),
            index + 3,
        )

    captured_ref = evd(20)
    captured_record = base.projection.evidence[evd(1)]
    assert captured_record.payload is not None
    captured_payload = replace(captured_record.payload, evidence_id=captured_ref)
    evidence = {
        **opaque,
        captured_ref: evidence_record(captured_payload, 20),
    }
    claim_recorded = base.projection.claims[clm(1)]
    assert claim_recorded.payload is not None
    claims = {
        clm(1): claim_record(
            replace(claim_recorded.payload, supporting_refs=tuple(evidence)),
            3,
        )
    }
    case = make_case(
        plans=base.projection.plans,
        obligations=base.projection.obligations,
        claims=claims,
        evidence=evidence,
        extra_refs=tuple(evidence),
    )
    scope = replace(
        scope,
        phase_bindings=((str(captured_ref), scope.phase_bindings[0][1]),),
    )
    return case, captured, scope, captured_ref


def test_structural_profile_sends_no_prose_and_declares_omitted_sections() -> None:
    case = _case_with_material()
    semantic = _build(case, ReviewContextProfile.STRUCTURAL)

    assert {item.category for item in semantic.items} == {DataCategory.BOUNDED_STRUCTURAL_METADATA}
    assert semantic.packet.goal_item_ids == ()
    assert semantic.packet.obligation_item_ids == ()
    assert semantic.packet.claim_item_ids == ()
    assert semantic.packet.targeted_excerpts == ()
    reasons = {item.reason for item in semantic.packet.omissions}
    assert "not_selected" in reasons
    # Timeline / frontier structural facts remain present.
    assert semantic.packet.timeline_item_ids
    assert all(item.section == "timeline" for item in semantic.items)


def test_goal_aware_profile_includes_bounded_goal_obligation_claim_with_categories() -> None:
    case = _case_with_material()
    semantic = _build(case, ReviewContextProfile.GOAL_AWARE)

    categories = {item.category for item in semantic.items}
    assert DataCategory.TASK_DESCRIPTION in categories
    assert DataCategory.OBLIGATION_TEXT in categories
    assert DataCategory.CLAIM_TEXT in categories
    assert semantic.packet.goal_item_ids
    assert semantic.packet.obligation_item_ids
    assert semantic.packet.claim_item_ids
    goal = next(item for item in semantic.items if item.section == "goal")
    assert b"Ship the review packet" in goal.content
    # Goal-aware still excludes targeted excerpts.
    assert semantic.packet.targeted_excerpts == ()


def test_provider_packet_preserves_detailed_frozen_history_by_category() -> None:
    records = replay_records("all-event-families")
    case = build_deterministic_case(replay(records), records, CaseAvailabilityFacts())
    semantic = _build(case, ReviewContextProfile.GOAL_AWARE)
    timeline = [
        item
        for item in semantic.items
        if item.item_id in semantic.packet.timeline_item_ids and item.item_id.startswith("history-")
    ]
    assert [item.occurred_order for item in timeline] == sorted(
        item.occurred_order for item in timeline
    )
    by_kind: dict[str, Mapping[str, JsonValue]] = {}
    for item in timeline:
        document = strict_json_parse(item.content)
        assert isinstance(document, Mapping)
        typed = cast(Mapping[str, JsonValue], document)
        kind = typed.get("kind")
        assert type(kind) is str
        assert typed["accepted_at"] is not None
        assert typed["occurred_at_consistency"] in {
            "within_forward_skew_allowance",
            "ahead_of_forward_skew_allowance",
        }
        by_kind[kind] = typed

    def payload_for(kind: str) -> Mapping[str, JsonValue]:
        payload = by_kind[kind]["payload"]
        assert isinstance(payload, Mapping)
        return cast(Mapping[str, JsonValue], payload)

    obligation = payload_for("obligation_published")
    assert obligation["acceptance_criteria"] == "All fixture assertions are reproducible offline."
    assert obligation["evidence_expectation"] == "A deterministic test-result snapshot"
    assert obligation["requested_items"] == [{"item_kind": "change", "value": "synthetic-replay"}]
    decision = payload_for("decision_recorded")
    assert (
        decision["rationale"] == "A deterministic command is the smallest complete public example."
    )
    action = payload_for("action_recorded")
    assert action["description"] == "Run the synthetic replay verification"
    assert action["attempted_items"] == ["synthetic-replay"]
    assert "command" not in action
    result = payload_for("result_recorded")
    assert result["summary"] == "Synthetic replay verification passed"
    evidence = payload_for("evidence_recorded")
    assert evidence["observed_at"] == "2026-03-02T00:00:08.000Z"
    assert evidence["strength"] == "immutable_snapshot"
    assert {
        "check_recorded",
        "response_recorded",
        "plan_published",
        "plan_revised",
    } <= by_kind.keys()
    categories = {(item.source_kind, item.category) for item in timeline}
    assert ("obligation", DataCategory.OBLIGATION_TEXT) in categories
    assert ("action", DataCategory.COMMAND_METADATA) in categories
    assert ("result", DataCategory.COMMAND_METADATA) in categories
    assert ("evidence", DataCategory.EVIDENCE_EXCERPT) in categories

    prepared = semantic_case_to_prepared_payload(
        semantic, {item.item_id for item in semantic.items}
    )
    provider_document = strict_json_parse(prepared)
    assert isinstance(provider_document, Mapping)
    provider_items = cast(Mapping[str, JsonValue], provider_document)["items"]
    assert isinstance(provider_items, list)
    provider_kinds: set[str] = set()
    for raw_item in provider_items:
        if not isinstance(raw_item, Mapping):
            continue
        item = cast(Mapping[str, JsonValue], raw_item)
        item_id = item.get("item_id")
        content = item.get("content")
        if type(item_id) is not str or not item_id.startswith("history-"):
            continue
        assert type(content) is str
        rendered = strict_json_parse(content.encode("utf-8"))
        assert isinstance(rendered, Mapping)
        kind = cast(Mapping[str, JsonValue], rendered).get("kind")
        assert type(kind) is str
        provider_kinds.add(kind)
    assert {
        "action_recorded",
        "check_recorded",
        "obligation_published",
        "plan_revised",
        "response_recorded",
        "result_recorded",
    } <= provider_kinds


def test_structural_history_has_no_recorded_prose_and_declares_omissions() -> None:
    records = replay_records("all-event-families")
    case = build_deterministic_case(replay(records), records, CaseAvailabilityFacts())
    semantic = _build(case, ReviewContextProfile.STRUCTURAL)
    history = [item for item in semantic.items if item.item_id.startswith("history-")]
    assert history
    assert {item.category for item in history} == {DataCategory.BOUNDED_STRUCTURAL_METADATA}
    assert all(b'"payload"' not in item.content for item in history)
    assert any(
        omission.reason == "not_selected" and omission.category is DataCategory.OBLIGATION_TEXT
        for omission in semantic.packet.omissions
    )


def test_assisted_profile_includes_only_linked_recorded_capped_excerpts() -> None:
    case = _case_with_material(with_evidence=True)
    findings = _findings_for(case)
    semantic = _build(case, ReviewContextProfile.ASSISTED, findings=findings)

    assert semantic.packet.targeted_excerpts
    excerpt = semantic.packet.targeted_excerpts[0]
    assert excerpt.source_kind == "test"
    assert excerpt.content_visibility == "available"
    body = next(item for item in semantic.items if item.item_id == excerpt.excerpt_item_id)
    assert body.content == b"test output: 1 failed assertion"
    assert set(excerpt.linked_subject_refs) <= (semantic.frontier_refs | semantic.local_check_refs)


def test_assisted_profile_canonicalizes_failure_excerpt_links_after_multiple_failures() -> None:
    base = _case_with_material(with_evidence=True)
    action_one = record(
        ActionRecordedPayload(
            action_id=act(1),
            action_kind=ActionKind.OTHER,
            description="First bounded attempt",
            obligation_refs=(obl(1),),
        ),
        5,
    )
    result_one = record(
        ResultRecordedPayload(
            result_id=res(1),
            action_id=act(1),
            outcome=ResultOutcome.FAILURE,
            summary="First attempt failed",
        ),
        6,
    )
    action_two = record(
        ActionRecordedPayload(
            action_id=act(2),
            action_kind=ActionKind.OTHER,
            description="Second bounded attempt",
            obligation_refs=(obl(1),),
        ),
        7,
    )
    result_two = record(
        ResultRecordedPayload(
            result_id=res(2),
            action_id=act(2),
            outcome=ResultOutcome.FAILURE,
            summary="Second attempt failed",
        ),
        8,
    )
    claim = record(
        ClaimRecordedPayloadV1_1(
            claim_id=clm(1),
            claim_kind=ClaimKind.COMPLETION,
            statement="Complete subject to two recorded limitations",
            supporting_refs=(evd(1),),
            obligation_refs=(obl(1),),
            limitation_refs=(res(1), res(2)),
        ),
        9,
    )
    case = make_case(
        plans=base.projection.plans,
        obligations=base.projection.obligations,
        actions={act(1): action_one, act(2): action_two},
        results={res(1): result_one, res(2): result_two},
        claims={clm(1): claim},
        evidence=base.projection.evidence,
        extra_refs=(clm(1), obl(1), evd(1), act(1), res(1), act(2), res(2)),
    )

    semantic = _build(case, ReviewContextProfile.ASSISTED)

    failure_excerpts = [
        excerpt for excerpt in semantic.packet.targeted_excerpts if excerpt.source_kind == "failure"
    ]
    assert len(failure_excerpts) == 2
    for excerpt in failure_excerpts:
        assert excerpt.linked_subject_refs == tuple(
            sorted(excerpt.linked_subject_refs, key=str.encode)
        )
        assert set(excerpt.linked_subject_refs) <= (
            semantic.frontier_refs | semantic.local_check_refs
        )


def _typed_digest_case(*, description: str | None) -> DeterministicCase:
    case = _case_with_material(with_evidence=True)
    record = case.projection.evidence[evd(1)]
    assert record.payload is not None
    typed_payload = EvidenceRecordedPayload(
        evidence_id=record.payload.evidence_id,
        evidence_kind=EvidenceKind.TEST_RESULT,
        strength=EvidenceImmutability.CONTENT_DIGEST,
        observed_at=record.payload.observed_at,
        content_digest="sha256:" + "1" * 64,
        description=description,
        digest_binding=EvidenceDigestBinding(
            subject=EvidenceDigestSubject.TEST_STDOUT,
            content_availability=EvidenceContentAvailability.DIGEST_ONLY,
            byte_count=512,
            provenance=EvidenceDigestProvenance.CALLER_ASSERTED,
        ),
    )
    return make_case(
        plans=case.projection.plans,
        obligations=case.projection.obligations,
        claims=case.projection.claims,
        evidence={evd(1): evidence_record(typed_payload, 4)},
        extra_refs=(clm(1), obl(1), evd(1)),
    )


def test_assisted_digest_excerpt_prefers_description_and_carries_provenance() -> None:
    typed = _typed_digest_case(description="caller prose the reviewer must be able to read")
    semantic = _build(typed, ReviewContextProfile.ASSISTED, findings=_findings_for(typed))
    excerpt = semantic.packet.targeted_excerpts[0]
    item = next(row for row in semantic.items if row.item_id == excerpt.excerpt_item_id)
    assert item.content == b"caller prose the reviewer must be able to read"
    provenance = excerpt.digest_provenance
    assert provenance is not None
    assert provenance.content_digest == "sha256:" + "1" * 64
    assert provenance.digest_subject is EvidenceDigestSubject.TEST_STDOUT
    assert provenance.content_availability is EvidenceContentAvailability.DIGEST_ONLY
    assert provenance.byte_count == 512
    assert provenance.provenance is EvidenceDigestProvenance.CALLER_ASSERTED
    assert provenance.evidence_kind is EvidenceKind.TEST_RESULT
    assert provenance.strength is EvidenceImmutability.CONTENT_DIGEST


def test_assisted_digest_excerpt_without_description_keeps_typed_provenance_text() -> None:
    typed = _typed_digest_case(description=None)
    semantic = _build(typed, ReviewContextProfile.ASSISTED, findings=_findings_for(typed))
    excerpt = semantic.packet.targeted_excerpts[0]
    item = next(row for row in semantic.items if row.item_id == excerpt.excerpt_item_id)
    document = strict_json_parse(item.content)
    assert isinstance(document, Mapping)
    assert document["digest_subject"] == "test_stdout"
    assert document["content_availability"] == "digest_only"
    assert excerpt.digest_provenance is not None


def _excerpt_provenance(**overrides: object) -> ExcerptDigestProvenance:
    fields: dict[str, object] = {
        "evidence_kind": EvidenceKind.TEST_RESULT,
        "strength": EvidenceImmutability.CONTENT_DIGEST,
        "content_digest": "sha256:" + "1" * 64,
        "digest_subject": EvidenceDigestSubject.TEST_STDOUT,
        "content_availability": EvidenceContentAvailability.DIGEST_ONLY,
        "byte_count": 512,
        "provenance": EvidenceDigestProvenance.CALLER_ASSERTED,
    }
    fields.update(overrides)
    return ExcerptDigestProvenance(**fields)  # type: ignore[arg-type]


def test_excerpt_digest_provenance_rejects_binding_invariant_violations() -> None:
    approval = {
        "approval_commitment": "sha256:" + "a" * 64,
        "approved_check_result_digest": "sha256:" + "b" * 64,
    }
    # Reserved subjects require their owning provenance.
    for subject, wrong in (
        (EvidenceDigestSubject.APPROVED_CHECK_RECEIPT, EvidenceDigestProvenance.CALLER_ASSERTED),
        (EvidenceDigestSubject.APPROVED_CHECK_RECEIPT, EvidenceDigestProvenance.IMPORT_OBSERVED),
        (EvidenceDigestSubject.IMPORT_REPORT, EvidenceDigestProvenance.CALLER_ASSERTED),
        (EvidenceDigestSubject.IMPORT_REPORT, EvidenceDigestProvenance.APPROVED_CHECK),
    ):
        with pytest.raises(ValueError, match="semantic_case_invalid"):
            _excerpt_provenance(
                digest_subject=subject,
                provenance=wrong,
                **(approval if wrong is EvidenceDigestProvenance.APPROVED_CHECK else {}),
            )
    # approved_check requires both approval digests, exactly.
    with pytest.raises(ValueError, match="semantic_case_invalid"):
        _excerpt_provenance(provenance=EvidenceDigestProvenance.APPROVED_CHECK)
    with pytest.raises(ValueError, match="semantic_case_invalid"):
        _excerpt_provenance(
            provenance=EvidenceDigestProvenance.APPROVED_CHECK,
            approval_commitment="sha256:" + "a" * 64,
        )
    with pytest.raises(ValueError, match="semantic_case_invalid"):
        _excerpt_provenance(**approval)
    accepted = _excerpt_provenance(
        digest_subject=EvidenceDigestSubject.APPROVED_CHECK_RECEIPT,
        provenance=EvidenceDigestProvenance.APPROVED_CHECK,
        **approval,
    )
    assert accepted.provenance is EvidenceDigestProvenance.APPROVED_CHECK


def test_case_envelope_serializes_excerpt_digest_provenance() -> None:
    typed = _typed_digest_case(description="caller prose the reviewer must be able to read")
    semantic = _build(typed, ReviewContextProfile.ASSISTED, findings=_findings_for(typed))
    document = strict_json_parse(bounded_case_envelope(semantic))
    assert isinstance(document, Mapping)
    packet = document["review_packet"]
    assert isinstance(packet, Mapping)
    rows = packet["targeted_excerpts"]
    assert isinstance(rows, list) and rows
    row = rows[0]
    assert isinstance(row, Mapping)
    provenance = row["digest_provenance"]
    assert isinstance(provenance, Mapping)
    assert provenance["content_digest"] == "sha256:" + "1" * 64
    assert provenance["digest_subject"] == "test_stdout"
    assert provenance["content_availability"] == "digest_only"
    assert provenance["byte_count"] == 512
    assert provenance["provenance"] == "caller_asserted"
    assert provenance["evidence_kind"] == "test_result"
    assert provenance["strength"] == "content_digest"
    assert "approval_commitment" not in provenance


@pytest.mark.parametrize("native", [True, False])
@pytest.mark.parametrize("omit_rows", [True, False])
def test_native_captured_excerpt_without_resolution_preserves_gap_despite_omission_cap(
    native: bool,
    omit_rows: bool,
) -> None:
    case = _case_with_material(with_evidence=True)
    record = case.projection.evidence[evd(1)]
    assert record.payload is not None
    payload = EvidenceRecordedPayload(
        evidence_id=record.payload.evidence_id,
        evidence_kind=EvidenceKind.OTHER,
        strength=EvidenceImmutability.IMMUTABLE_SNAPSHOT,
        observed_at=record.payload.observed_at,
        captured_object_id=object_id("obj_00000000-0000-4000-8000-000000000302"),
        content_digest="sha256:" + "3" * 64,
        description="Observation-captured tool output bytes part=1/1",
        digest_binding=EvidenceDigestBinding(
            subject=EvidenceDigestSubject.BOUNDED_EXCERPT,
            content_availability=EvidenceContentAvailability.CAPTURED,
            byte_count=512,
            provenance=(
                EvidenceDigestProvenance.OBSERVATION_CAPTURED
                if native
                else EvidenceDigestProvenance.CALLER_ASSERTED
            ),
        ),
    )
    observed = make_case(
        plans=case.projection.plans,
        obligations=case.projection.obligations,
        claims=case.projection.claims,
        evidence={evd(1): evidence_record(payload, 4)},
        extra_refs=(clm(1), obl(1), evd(1)),
    )
    selection = ReviewSelectionPolicy.for_profile(ReviewContextProfile.ASSISTED)
    if omit_rows:
        selection = replace(selection, max_omissions=0)
    semantic = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=observed,
        dependency_digest="sha256:" + "b" * 64,
        findings=_findings_for(observed),
        review_context_profile=ReviewContextProfile.ASSISTED,
        review_selection=selection,
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
    )
    if not native:
        assert semantic.packet.targeted_excerpts
        assert any(
            item.content == b"Observation-captured tool output bytes part=1/1"
            for item in semantic.items
        )
        return
    assert semantic.packet.targeted_excerpts == ()
    if not omit_rows:
        assert any(
            row.subject_ref == evd(1) and row.reason == "not_recorded"
            for row in semantic.packet.omissions
        )
    assert "captured_object_unavailable" in semantic.packet.coverage.known_gaps
    assert semantic.packet.coverage.ledger_freshness is LedgerFreshness.PARTIAL
    assert b"Observation-captured tool output bytes" not in bounded_case_envelope(semantic)


def test_authenticated_captured_bytes_reach_selected_case_and_prepared_packet() -> None:
    case, captured, scope = _captured_case_values()
    semantic = _build(
        case,
        ReviewContextProfile.ASSISTED,
        findings=_findings_for(case),
        captured_content=(captured,),
        captured_content_scope=scope,
    )

    excerpt = next(item for item in semantic.items if item.item_id == f"excerpt-{evd(1)}")
    assert excerpt.content == captured.content
    assert semantic.packet.targeted_excerpts[0].content_visibility == "available"
    # The pre-egress case envelope is structural metadata only.
    assert captured.content not in bounded_case_envelope(semantic)

    # The privacy-approved projection is the first point at which the actual
    # authenticated retained bytes are assembled into the provider packet.
    prepared = semantic_case_to_prepared_payload(
        semantic,
        {item.item_id for item in semantic.items},
    )
    assert captured.content in prepared


def test_authenticated_capture_is_selected_before_opaque_metadata_rows() -> None:
    case, captured, scope, captured_ref = _opaque_before_capture_case()

    # Seventeen candidates under a 16-excerpt limit (the 1.1.0 Expanded preset), so the capture
    # has to win a slot rather than merely fit (issue #907 Phase 1b lifts the current preset).
    semantic = _build(
        case,
        ReviewContextProfile.EXPANDED,
        captured_content=(captured,),
        captured_content_scope=scope,
        selection=ReviewSelectionPolicy.for_profile(
            ReviewContextProfile.EXPANDED, preset_version="1.1.0"
        ),
    )

    assert len(semantic.packet.targeted_excerpts) == 16
    selected = semantic.packet.targeted_excerpts[0]
    assert selected.excerpt_item_id == f"excerpt-{captured_ref}"
    assert selected.content_visibility == "available"
    assert selected.digest_provenance is not None
    assert selected.digest_provenance.provenance is EvidenceDigestProvenance.OBSERVATION_CAPTURED
    selected_item = next(
        item for item in semantic.items if item.item_id == selected.excerpt_item_id
    )
    assert selected_item.content == captured.content

    metadata_rows = semantic.packet.targeted_excerpts[1:]
    assert len(metadata_rows) == 15
    assert all(row.content_visibility == "available" for row in metadata_rows)
    assert all(row.digest_provenance is None for row in metadata_rows)
    # Sixteen metadata rows compete for fifteen remaining slots: the one the count cuts is an
    # omission and, since issue #907, also discloses ``content_unselected`` like a captured cut.
    assert "content_unselected" in semantic.packet.coverage.known_gaps


def test_captured_multipart_group_is_one_deterministic_excerpt() -> None:
    case, captured, scope, captured_ref = _opaque_before_capture_case()
    first = b"captured-part-a"
    second = b"captured-part-b"
    first_digest = "sha256:" + hashlib.sha256(first).hexdigest()
    second_digest = "sha256:" + hashlib.sha256(second).hexdigest()
    first_object = object_id("obj_00000000-0000-4000-8000-000000000302")
    second_object = object_id("obj_00000000-0000-4000-8000-000000000303")
    first_envelope = "sha256:" + "5" * 64
    second_envelope = "sha256:" + "9" * 64
    captured_ref_two = evd(21)

    first_payload = EvidenceRecordedPayload(
        evidence_id=captured_ref,
        evidence_kind=EvidenceKind.OTHER,
        strength=EvidenceImmutability.IMMUTABLE_SNAPSHOT,
        observed_at=timestamp_from_string("2026-07-01T00:00:00.000Z"),
        captured_object_id=first_object,
        content_digest=first_digest,
        description="Observation-captured tool output bytes part=1/2",
        digest_binding=EvidenceDigestBinding(
            subject=EvidenceDigestSubject.BOUNDED_EXCERPT,
            content_availability=EvidenceContentAvailability.CAPTURED,
            byte_count=len(first),
            provenance=EvidenceDigestProvenance.OBSERVATION_CAPTURED,
        ),
    )
    first_binding = first_payload.digest_binding
    assert type(first_binding) is EvidenceDigestBinding
    second_payload = replace(
        first_payload,
        evidence_id=captured_ref_two,
        captured_object_id=second_object,
        content_digest=second_digest,
        description="Observation-captured tool output bytes part=2/2",
        digest_binding=replace(first_binding, byte_count=len(second)),
    )
    evidence = dict(case.projection.evidence)
    evidence[captured_ref] = evidence_record(first_payload, 20)
    evidence[captured_ref_two] = evidence_record(second_payload, 21)
    claim_recorded = case.projection.claims[clm(1)]
    assert claim_recorded.payload is not None
    claims = {
        clm(1): claim_record(
            replace(
                claim_recorded.payload,
                supporting_refs=tuple(evidence),
            ),
            3,
        )
    }
    case = make_case(
        plans=case.projection.plans,
        obligations=case.projection.obligations,
        claims=claims,
        evidence=evidence,
        extra_refs=tuple(evidence),
    )
    first_manifest = replace(
        captured.manifest,
        object_id=first_object,
        envelope_digest=first_envelope,
        part_index=0,
        part_count=2,
        content_digest=first_digest,
        content_bytes=len(first),
    )
    first_ref = replace(
        captured.object_ref,
        object_id=first_object,
        envelope_digest=first_envelope,
    )
    first_captured = replace(
        captured,
        object_ref=first_ref,
        manifest=first_manifest,
        content=first,
    )
    second_manifest = replace(
        captured.manifest,
        object_id=second_object,
        envelope_digest=second_envelope,
        part_index=1,
        part_count=2,
        content_digest=second_digest,
        content_bytes=len(second),
    )
    second_ref = replace(
        captured.object_ref,
        object_id=second_object,
        envelope_digest=second_envelope,
    )
    second_captured = replace(
        captured,
        object_ref=second_ref,
        manifest=second_manifest,
        content=second,
    )
    scope = replace(
        scope,
        phase_bindings=(
            (str(captured_ref), scope.phase_bindings[0][1]),
            (str(captured_ref_two), scope.phase_bindings[0][1]),
        ),
    )

    semantic = _build(
        case,
        ReviewContextProfile.EXPANDED,
        captured_content=(second_captured, first_captured),
        captured_content_scope=scope,
    )

    selected = semantic.packet.targeted_excerpts[0]
    assert selected.excerpt_item_id == f"excerpt-{captured_ref}"
    selected_item = next(
        item for item in semantic.items if item.item_id == selected.excerpt_item_id
    )
    assert selected_item.content == first + second
    assert selected.content_bytes == len(first + second)
    assert selected.digest_provenance is not None
    assert selected.digest_provenance.content_digest == (
        "sha256:" + hashlib.sha256(first + second).hexdigest()
    )
    assert all(
        f"excerpt-{ref}" not in {item.excerpt_item_id for item in semantic.packet.targeted_excerpts}
        for ref in (captured_ref_two,)
    )


def test_capture_budget_selects_newest_capture_and_discloses_the_rest() -> None:
    """Unreserved captures compete by recency (issue #907); the loser is disclosed, not lost."""

    case, captured, scope, captured_ref = _opaque_before_capture_case()
    second_ref = evd(21)
    second_content = b"second-capture"
    second_digest = "sha256:" + hashlib.sha256(second_content).hexdigest()
    second_object = object_id("obj_00000000-0000-4000-8000-000000000303")
    second_envelope = "sha256:" + "9" * 64
    source_payload = case.projection.evidence[captured_ref].payload
    assert type(source_payload) is EvidenceRecordedPayload
    source_binding = source_payload.digest_binding
    assert type(source_binding) is EvidenceDigestBinding
    second_payload = replace(
        source_payload,
        evidence_id=second_ref,
        captured_object_id=second_object,
        content_digest=second_digest,
        description="Observation-captured tool output bytes part=1/1",
        digest_binding=replace(
            source_binding,
            byte_count=len(second_content),
        ),
    )
    evidence = dict(case.projection.evidence)
    evidence[second_ref] = evidence_record(second_payload, 21)
    claim_recorded = case.projection.claims[clm(1)]
    assert claim_recorded.payload is not None
    claims = {
        clm(1): claim_record(
            replace(claim_recorded.payload, supporting_refs=tuple(evidence)),
            3,
        )
    }
    case = make_case(
        plans=case.projection.plans,
        obligations=case.projection.obligations,
        claims=claims,
        evidence=evidence,
        extra_refs=tuple(evidence),
    )
    second_manifest = replace(
        captured.manifest,
        object_id=second_object,
        envelope_digest=second_envelope,
        correlation_identity="tool-use-2",
        source_commitment="hmac-sha256:" + "a" * 64,
        content_digest=second_digest,
        content_bytes=len(second_content),
    )
    second_ref_object = replace(
        captured.object_ref,
        object_id=second_object,
        envelope_digest=second_envelope,
    )
    second_captured = replace(
        captured,
        object_ref=second_ref_object,
        manifest=second_manifest,
        content=second_content,
    )
    scope = replace(
        scope,
        phase_bindings=(
            (str(captured_ref), scope.phase_bindings[0][1]),
            (str(second_ref), scope.phase_bindings[0][1]),
        ),
    )
    selection = replace(
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED),
        max_total_excerpt_bytes=len(captured.content),
    )
    semantic = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.EXPANDED,
        review_selection=selection,
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        captured_content=(second_captured, captured),
        captured_content_scope=scope,
    )

    assert [item.excerpt_item_id for item in semantic.packet.targeted_excerpts] == [
        f"excerpt-{second_ref}"
    ]
    assert "content_unselected" in semantic.packet.coverage.known_gaps
    assert any(
        omission.subject_ref == str(captured_ref) and omission.reason == "not_selected"
        for omission in semantic.packet.omissions
    )

    replayed_case = make_case(
        plans=case.projection.plans,
        obligations=case.projection.obligations,
        claims=claims,
        evidence=dict(reversed(tuple(evidence.items()))),
        extra_refs=tuple(reversed(tuple(evidence))),
    )
    replayed = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=replayed_case,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.EXPANDED,
        review_selection=selection,
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        captured_content=(captured, second_captured),
        captured_content_scope=scope,
    )
    assert replayed.case_digest == semantic.case_digest
    assert replayed.packet.targeted_excerpts == semantic.packet.targeted_excerpts


def test_authenticated_capture_excluded_by_zero_excerpt_selection_is_disclosed() -> None:
    case, captured, scope = _captured_case_values()
    selection = ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL)
    semantic = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.CUSTOM,
        review_selection=selection,
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        captured_content=(captured,),
        captured_content_scope=scope,
    )

    assert semantic.packet.targeted_excerpts == ()
    assert "content_unselected" in semantic.packet.coverage.known_gaps
    assert any(
        omission.subject_ref == str(evd(1))
        and omission.source_kind == "evidence"
        and omission.reason == "not_selected"
        for omission in semantic.packet.omissions
    )
    assert captured.content not in semantic_case_to_prepared_payload(
        semantic,
        {item.item_id for item in semantic.items},
    )


def test_authenticated_capture_excluded_by_excerpt_kind_is_disclosed() -> None:
    case, captured, scope = _captured_case_values()
    selection = replace(
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED),
        excerpt_kinds=("test",),
    )
    semantic = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.CUSTOM,
        review_selection=selection,
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        captured_content=(captured,),
        captured_content_scope=scope,
    )

    assert semantic.packet.targeted_excerpts == ()
    assert "content_unselected" in semantic.packet.coverage.known_gaps
    assert any(
        omission.subject_ref == str(evd(1))
        and omission.source_kind == "evidence"
        and omission.reason == "not_selected"
        for omission in semantic.packet.omissions
    )
    assert captured.content not in semantic_case_to_prepared_payload(
        semantic,
        {item.item_id for item in semantic.items},
    )


def test_authenticated_capture_excluded_by_assisted_relevance_is_disclosed() -> None:
    case, captured, scope = _captured_case_values()
    claim_recorded = case.projection.claims[clm(1)]
    assert claim_recorded.payload is not None
    unlinked_case = make_case(
        plans=case.projection.plans,
        obligations=case.projection.obligations,
        claims={
            clm(1): claim_record(
                replace(claim_recorded.payload, supporting_refs=()),
                3,
            )
        },
        evidence=case.projection.evidence,
        extra_refs=(clm(1), obl(1), evd(1)),
    )
    semantic = _build(
        unlinked_case,
        ReviewContextProfile.ASSISTED,
        captured_content=(captured,),
        captured_content_scope=scope,
    )

    assert semantic.packet.targeted_excerpts == ()
    assert "content_unselected" in semantic.packet.coverage.known_gaps
    assert any(
        omission.subject_ref == str(evd(1))
        and omission.source_kind == "evidence"
        and omission.reason == "not_selected"
        for omission in semantic.packet.omissions
    )
    assert captured.content not in semantic_case_to_prepared_payload(
        semantic,
        {item.item_id for item in semantic.items},
    )


def test_wrong_phase_captured_bytes_are_excluded_even_with_valid_digest() -> None:
    case, captured, scope = _captured_case_values()
    wrong_phase = replace(captured, phase_identity="sha256:" + "9" * 64)
    semantic = _build(
        case,
        ReviewContextProfile.ASSISTED,
        findings=_findings_for(case),
        captured_content=(wrong_phase,),
        captured_content_scope=scope,
    )

    assert all(item.item_id != f"excerpt-{evd(1)}" for item in semantic.items)
    assert "captured_object_unavailable" in semantic.packet.coverage.known_gaps
    assert captured.content not in semantic_case_to_prepared_payload(
        semantic,
        {item.item_id for item in semantic.items},
    )
    assert "content_unselected" in semantic.packet.coverage.known_gaps


def test_redacted_captured_bytes_remain_available_with_explicit_gap() -> None:
    case, captured, scope = _captured_case_values(redacted=True)
    semantic = _build(
        case,
        ReviewContextProfile.ASSISTED,
        findings=_findings_for(case),
        captured_content=(captured,),
        captured_content_scope=scope,
    )

    excerpt = next(item for item in semantic.items if item.item_id == f"excerpt-{evd(1)}")
    assert excerpt.content == captured.content
    assert "content_redacted" in semantic.packet.coverage.known_gaps


def test_selection_clipping_marks_partial_coverage_only_when_excerpt_is_admitted() -> None:
    case, captured, scope = _captured_case_values()
    selection = replace(
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED),
        max_excerpt_bytes=8,
    )
    semantic = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=_findings_for(case),
        review_context_profile=ReviewContextProfile.EXPANDED,
        review_selection=selection,
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        captured_content=(captured,),
        captured_content_scope=scope,
    )
    assert semantic.packet.coverage.ledger_freshness is LedgerFreshness.PARTIAL
    assert "truncated_payload" in semantic.packet.coverage.known_gaps
    excerpt = semantic.packet.targeted_excerpts[0]
    assert excerpt.content_bytes == 8

    omitted_selection = replace(selection, max_total_excerpt_bytes=1)
    omitted = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=_findings_for(case),
        review_context_profile=ReviewContextProfile.EXPANDED,
        review_selection=omitted_selection,
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        captured_content=(captured,),
        captured_content_scope=scope,
    )
    assert "truncated_payload" not in omitted.packet.coverage.known_gaps
    assert "content_unselected" in omitted.packet.coverage.known_gaps
    assert "content_capture_unavailable" not in omitted.packet.coverage.known_gaps


def test_captured_content_input_is_bounded_before_grouping() -> None:
    case, captured, scope = _captured_case_values()
    with pytest.raises(ValueError, match="over_limit"):
        _build(
            case,
            ReviewContextProfile.ASSISTED,
            captured_content=tuple(captured for _ in range(65)),
            captured_content_scope=scope,
        )

    large_case, large_capture, large_scope = _captured_case_values(b"x" * 300_000)
    with pytest.raises(ValueError, match="over_limit"):
        _build(
            large_case,
            ReviewContextProfile.ASSISTED,
            captured_content=tuple(large_capture for _ in range(7)),
            captured_content_scope=large_scope,
        )


def test_assisted_legacy_digest_is_an_explicit_omission() -> None:
    case = _case_with_material(with_evidence=True)
    record = case.projection.evidence[evd(1)]
    assert record.payload is not None
    legacy_payload = EvidenceRecordedPayload(
        evidence_id=record.payload.evidence_id,
        evidence_kind=EvidenceKind.TEST_RESULT,
        strength=EvidenceImmutability.CONTENT_DIGEST,
        observed_at=record.payload.observed_at,
        content_digest="sha256:" + "2" * 64,
        description="legacy prose",
    )
    legacy = make_case(
        plans=case.projection.plans,
        obligations=case.projection.obligations,
        claims=case.projection.claims,
        evidence={evd(1): evidence_record(legacy_payload, 4)},
        extra_refs=(clm(1), obl(1), evd(1)),
    )
    semantic = _build(legacy, ReviewContextProfile.ASSISTED, findings=_findings_for(legacy))
    assert semantic.packet.targeted_excerpts == ()
    assert any(
        omission.subject_ref == evd(1) and omission.reason == "not_recorded"
        for omission in semantic.packet.omissions
    )


def test_withheld_and_not_selected_material_use_correct_omission_reasons() -> None:
    case = _case_with_material()
    structural = _build(case, ReviewContextProfile.STRUCTURAL)
    omitted = {
        (item.source_kind, item.reason, item.category) for item in structural.packet.omissions
    }
    assert ("task", "not_selected", DataCategory.TASK_DESCRIPTION) in omitted
    assert ("obligation", "not_selected", DataCategory.OBLIGATION_TEXT) in omitted
    assert ("claim", "not_selected", DataCategory.CLAIM_TEXT) in omitted

    # No recorded decision → no decision prose under goal-aware, no invented content.
    goal_aware = _build(case, ReviewContextProfile.GOAL_AWARE)
    assert goal_aware.packet.decision_item_ids == ()
    assert not any(item.section == "decision" for item in goal_aware.items)


def test_every_supplied_ref_belongs_to_frozen_allowlist() -> None:
    case = _case_with_material(with_evidence=True)
    findings = _findings_for(case)
    semantic = _build(case, ReviewContextProfile.ASSISTED, findings=findings)
    allowed = semantic.frontier_refs | semantic.local_check_refs

    for item in semantic.items:
        assert set(item.linked_subject_refs) <= allowed
    for assessment in semantic.packet.deterministic_assessments:
        assert assessment.finding_ref in semantic.local_check_refs
        assert set(assessment.subject_refs) <= semantic.frontier_refs
        assert set(assessment.supporting_refs) <= allowed
    for omission in semantic.packet.omissions:
        assert omission.subject_ref in allowed


def test_deterministic_finding_basis_and_evidence_produce_projected_assessment() -> None:
    case = _case_with_material(with_evidence=True)
    findings = _findings_for(case)
    assert findings
    semantic = _build(case, ReviewContextProfile.ASSISTED, findings=findings)

    assert semantic.packet.deterministic_assessments
    assessment = semantic.packet.deterministic_assessments[0]
    assert assessment.observed_facts
    assert assessment.summary_item_id is not None
    assert assessment.detail_item_id is not None
    summary = next(item for item in semantic.items if item.item_id == assessment.summary_item_id)
    assert summary.category is DataCategory.FINDING_SUMMARY
    assert summary.source_ref == str(assessment.finding_ref)


def test_case_and_dependency_changes_invalidate_case_digest() -> None:
    case = _case_with_material()
    left = _build(case, ReviewContextProfile.GOAL_AWARE, dependency="sha256:" + "b" * 64)
    right = _build(case, ReviewContextProfile.GOAL_AWARE, dependency="sha256:" + "c" * 64)
    assert left.case_digest != right.case_digest

    other = _case_with_material(with_evidence=False)
    third = _build(other, ReviewContextProfile.GOAL_AWARE, dependency="sha256:" + "b" * 64)
    assert left.case_digest != third.case_digest


def test_case_builder_performs_no_ambient_state_access() -> None:
    source = inspect.getsource(build_semantic_case)
    # Capability-free contract: no ambient import or runner symbols in the builder body.
    for forbidden in (
        "subprocess",
        "Path(",
        "open(",
        "os.environ",
        "socket",
        "Git",
        "filesystem",
        "transcript",
        "httpx",
        "aiohttp",
    ):
        assert forbidden not in source


def test_candidate_context_preserves_item_categories_and_packet_envelope() -> None:
    case = _case_with_material(with_evidence=True)
    findings = _findings_for(case)
    semantic = _build(case, ReviewContextProfile.ASSISTED, findings=findings)
    scope = AuthorizationScope(
        AuthorizationScopeKind.TASK,
        "ins_10000000-0000-4000-8000-000000000001",
        "hmac-sha256:" + "a" * 64,
        "tsk_10000000-0000-4000-8000-000000000001",
    )
    binding = ProviderBinding("fake", "model", "profile", "1.0.0", "external")
    candidate = semantic_case_to_candidate_context(
        semantic,
        request_id="req_10000000-0000-4000-8000-000000000001",
        scope=scope,
        provider_binding=binding,
    )
    assert candidate.purpose == "semantic-review"
    assert candidate.subject_digest == semantic.case_digest
    assert candidate.items[0].item_id == REVIEW_PACKET_ITEM_ID
    assert candidate.items[0].category is DataCategory.BOUNDED_STRUCTURAL_METADATA
    categories = {item.category for item in candidate.items[1:]}
    assert DataCategory.TASK_DESCRIPTION in categories
    assert DataCategory.EVIDENCE_EXCERPT in categories or DataCategory.FINDING_SUMMARY in categories


def test_prepared_payload_binds_selected_packet_and_withheld_omissions() -> None:
    case = _case_with_material(with_evidence=True)
    findings = _findings_for(case)
    semantic = _build(case, ReviewContextProfile.ASSISTED, findings=findings)
    # Approve only structural timeline + envelope-equivalent content subset.
    included = {
        item.item_id
        for item in semantic.items
        if item.category is DataCategory.BOUNDED_STRUCTURAL_METADATA
    }
    payload = semantic_case_to_prepared_payload(semantic, included)
    assert b"yoetz.review-packet-case/2" in payload
    document = strict_json_parse(payload)
    assert isinstance(document, dict)
    packet = document.get("review_packet")
    assert isinstance(packet, dict)
    omissions = packet.get("omissions")
    assert isinstance(omissions, list)
    reasons: set[str] = set()
    for row in omissions:
        if isinstance(row, dict):
            reason = row.get("reason")
            if type(reason) is str:
                reasons.add(reason)
    assert "withheld_by_policy" in reasons
    raw_items = document.get("items")
    assert isinstance(raw_items, list)
    item_ids: set[str] = set()
    for row in raw_items:
        if isinstance(row, dict):
            item_id = row.get("item_id")
            if type(item_id) is str:
                item_ids.add(item_id)
    assert item_ids == included
    assert semantic.case_digest.encode("ascii") in payload


def test_review_selection_digest_is_stable() -> None:
    left = review_selection_digest(ReviewSelectionPolicy.for_profile(ReviewContextProfile.ASSISTED))
    right = review_selection_digest(
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.ASSISTED)
    )
    assert left == right
    structural = review_selection_digest(
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL)
    )
    assert left != structural


def test_structural_assessments_have_no_finding_prose_items() -> None:
    case = _case_with_material()
    findings = _findings_for(case)
    semantic = _build(case, ReviewContextProfile.STRUCTURAL, findings=findings)
    assert all(
        assessment.summary_item_id is None and assessment.detail_item_id is None
        for assessment in semantic.packet.deterministic_assessments
    )
    assert not any(
        item.section in {"deterministic_summary", "deterministic_detail"} for item in semantic.items
    )


def test_prepared_payload_names_the_refs_post_validation_will_accept() -> None:
    """The reviewer gets one list of citable ids, matching the fence exactly.

    The ids most visible in the document — ``items[].item_id``, e.g. ``goal-3`` — are not citable
    at all, so the accept set is stated explicitly instead of left to be inferred. It names only
    refs whose content the packet carries (TB4 tb4v1, issue #976): advertising every frontier ref,
    including ones whose rows were omitted, invited citations post-validation had to remove.
    """

    case = _case_with_material(with_evidence=True)
    findings = _findings_for(case)
    semantic = _build(case, ReviewContextProfile.ASSISTED, findings=findings)
    included = {item.item_id for item in semantic.items}
    document = strict_json_parse(semantic_case_to_prepared_payload(semantic, included))
    assert isinstance(document, dict)

    raw_citable = document.get("citable_refs")
    assert isinstance(raw_citable, list)
    citable = [ref for ref in cast(list[object], raw_citable) if type(ref) is str]
    assert len(citable) == len(raw_citable)
    assert citable == sorted(citable)
    assert citable

    raw_items = document.get("items")
    assert isinstance(raw_items, list)
    item_ids: set[str] = set()
    carried: set[str] = set()
    for row in cast(list[object], raw_items):
        if isinstance(row, dict):
            typed = cast(dict[str, object], row)
            item_id = typed.get("item_id")
            if type(item_id) is str:
                item_ids.add(item_id)
            source = typed.get("source_ref")
            if type(source) is str:
                carried.add(source)
            linked = typed.get("linked_subject_refs")
            if isinstance(linked, list):
                carried.update(ref for ref in cast(list[object], linked) if type(ref) is str)
    raw_assessments = cast(dict[str, object], document["review_packet"]).get(
        "deterministic_assessments"
    )
    assert isinstance(raw_assessments, list)
    for row in cast(list[object], raw_assessments):
        if isinstance(row, dict):
            ref = cast(dict[str, object], row).get("finding_ref")
            if type(ref) is str:
                carried.add(ref)
    fence = semantic.frontier_refs | semantic.local_check_refs
    assert set(citable) == carried & fence
    # A frontier ref with no carried row is not advertised.
    assert fence - set(citable)
    # The two vocabularies are disjoint: an item_id is never a citable ref.
    assert not item_ids & set(citable)

    # The advertised set is exactly what post-validation can prove was sent: the provider-bound
    # text index read back from the same bytes, including local findings' assessment rows.
    prepared = semantic_case_to_prepared_payload(semantic, included)
    disclosure = review_packet_disclosure_result(prepared).disclosure
    assert disclosure is not None
    assert set(citable) == set(disclosure.provider_input_text_by_ref) & fence
    assert semantic.local_check_refs & set(citable)
    for ref in semantic.local_check_refs & set(citable):
        assert any(
            '"finding_ref":"' + ref + '"' in text
            for text in disclosure.provider_input_text_by_ref[ref]
        )
        # The indexed assessment text is a verbatim slice of the sent bytes, not a re-encoding.
        for text in disclosure.provider_input_text_by_ref[ref]:
            assert text.encode("utf-8") in prepared


def _case_with_long_evidence(description: str) -> DeterministicCase:
    """The same shape as ``_case_with_material``, with one oversized evidence description."""

    plan = plan_record(PlanPublishedPayload(1, "Ship the review packet", (obl(1),)), 1)
    obligation = obligation_record(
        ObligationPublishedPayload(
            obl(1), "Build the real packet", "tests pass", ObligationStatus.OPEN
        ),
        2,
    )
    claim = record(
        ClaimRecordedPayload(
            clm(1),
            ClaimKind.COMPLETION,
            "Work is complete",
            (evd(1),),
            obligation_refs=(obl(1),),
        ),
        3,
    )
    evidence = {
        evd(1): evidence_record(
            EvidenceRecordedPayload(
                evd(1),
                EvidenceKind.TEST_RESULT,
                EvidenceImmutability.METADATA_ONLY,
                timestamp_from_string("2026-07-01T00:00:00.000Z"),
                description=description,
            ),
            4,
        )
    }
    return make_case(
        plans={1: plan},
        obligations={obl(1): obligation},
        claims={clm(1): claim},
        evidence=evidence,
        extra_refs=(clm(1), obl(1), evd(1)),
    )


def test_excerpt_honors_the_approved_per_excerpt_bound_instead_of_the_4_kib_item_clip() -> None:
    """A recorded description the selection admits reaches the reviewer whole (issue #907).

    Publish-side prose accepts up to ``MAX_TEXT_BYTES`` (8192). Excerpts used to be clipped at
    ``MAX_REVIEW_TEXT_BYTES`` (4096) although the approved Assisted and Expanded policies allow
    16 KiB per excerpt, so a 5 KB description arrived as a fragment. The approved bound now
    applies; nothing is widened past what the owner approved.
    """

    body = "e" * 5_000
    assert len(body.encode("utf-8")) <= MAX_TEXT_BYTES
    assert len(body.encode("utf-8")) > MAX_REVIEW_TEXT_BYTES
    assert ReviewSelectionPolicy.for_profile(ReviewContextProfile.ASSISTED).max_excerpt_bytes > len(
        body.encode("utf-8")
    )

    case = _case_with_long_evidence(body)
    semantic = _build(case, ReviewContextProfile.ASSISTED, findings=_findings_for(case))

    excerpt = next(item for item in semantic.items if item.item_id == f"excerpt-{evd(1)}")
    assert excerpt.content == body.encode("utf-8")
    assert SEMANTIC_CASE_CONTENT_OVER_ITEM_LIMIT_GAP not in semantic.packet.coverage.known_gaps
    assert "truncated_payload" not in semantic.packet.coverage.known_gaps


def test_narrow_custom_excerpt_bound_is_selection_not_a_size_gap() -> None:
    """Clipping at a custom ``max_excerpt_bytes`` below the item bound raises no size gap.

    The excerpt bound is the selection policy's declared choice — the packet metadata carries
    ``max_excerpt_bytes`` — so a reviewer can already attribute the shortening. Only the
    per-item case bound (``MAX_REVIEW_TEXT_BYTES``) names a size drop the selection accepted.
    """

    body = "e" * 1_000
    narrow = replace(
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.ASSISTED),
        max_excerpt_bytes=512,
    )
    case = _case_with_long_evidence(body)
    semantic = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=_findings_for(case),
        review_context_profile=ReviewContextProfile.ASSISTED,
        review_selection=narrow,
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
    )

    excerpt = next(item for item in semantic.items if item.item_id == f"excerpt-{evd(1)}")
    assert excerpt.content_bytes == 512
    assert SEMANTIC_CASE_CONTENT_OVER_ITEM_LIMIT_GAP not in semantic.packet.coverage.known_gaps
    manifest = semantic.packet.input_manifest
    assert manifest is not None
    assert manifest.latest_verification.status == "partial"
    assert "truncated_payload" in manifest.latest_verification.omission_reasons

    prepared = cast(
        dict[str, JsonValue],
        strict_json_parse(
            semantic_case_to_prepared_payload(semantic, {item.item_id for item in semantic.items})
        ),
    )
    provider = cast(
        dict[str, JsonValue],
        cast(dict[str, JsonValue], prepared["review_packet"])["provider_input_manifest"],
    )
    verification = cast(dict[str, JsonValue], provider["latest_verification"])
    assert verification["status"] == "partial"
    assert "truncated_payload" in cast(list[JsonValue], verification["omission_reasons"])


def test_prose_within_the_case_item_bound_raises_no_over_limit_gap() -> None:
    body = "e" * 1_000
    case = _case_with_long_evidence(body)
    semantic = _build(case, ReviewContextProfile.ASSISTED, findings=_findings_for(case))

    excerpt = next(item for item in semantic.items if item.item_id == f"excerpt-{evd(1)}")
    assert excerpt.content == body.encode("utf-8")
    assert SEMANTIC_CASE_CONTENT_OVER_ITEM_LIMIT_GAP not in semantic.packet.coverage.known_gaps


def test_oversized_plan_prose_is_clipped_with_both_ends_instead_of_replaced_by_a_digest() -> None:
    """An oversized plan keeps its structure and readable prose (issue #907).

    ``_bounded_json`` used to swap the entire payload for a ``yoetz.bounded-content-omission/1``
    digest marker, leaving the reviewer nothing to read. The longest prose field is now clipped
    with its head and tail kept and the cut marked, and coverage still names the size drop.
    """

    summary = "START " + "s" * 6_000 + " END"
    plan = plan_record(PlanPublishedPayload(1, summary, (obl(1),)), 1)
    obligation = obligation_record(
        ObligationPublishedPayload(
            obl(1), "Build the real packet", "tests pass", ObligationStatus.OPEN
        ),
        2,
    )
    case = make_case(
        plans={1: plan},
        obligations={obl(1): obligation},
        extra_refs=(obl(1),),
    )
    semantic = _build(case, ReviewContextProfile.GOAL_AWARE)

    goal = next(item for item in semantic.items if item.section == "goal")
    assert goal.content_bytes <= MAX_REVIEW_TEXT_BYTES
    body = strict_json_parse(goal.content)
    assert isinstance(body, dict)
    assert "schema" not in body
    assert body["obligation_refs"] == [str(obl(1))]
    clipped = body["summary"]
    assert isinstance(clipped, str)
    assert clipped.startswith("START ") and clipped.endswith(" END")
    assert "bytes elided here; head and tail kept]" in clipped
    assert SEMANTIC_CASE_CONTENT_OVER_ITEM_LIMIT_GAP in semantic.packet.coverage.known_gaps
    # The payload was carried, clipped: it is not reported as a section the profile declined.
    assert not any(
        omission.category is DataCategory.TASK_DESCRIPTION for omission in semantic.packet.omissions
    )


def test_payload_without_clippable_prose_still_falls_back_to_the_named_marker() -> None:
    """When no single prose field is long enough to clip, the digest marker says why."""

    value: dict[str, JsonValue] = {f"field_{index:02d}": "x" * 200 for index in range(40)}
    text, fit = semantic_case_module._bounded_json(value)  # pyright: ignore[reportPrivateUsage]

    marker = strict_json_parse(text.encode("utf-8"))
    assert fit == "replaced"
    assert isinstance(marker, dict)
    assert marker["schema"] == "yoetz.bounded-content-omission/1"
    assert marker["reason"] == OVER_CASE_ITEM_LIMIT_REASON


@pytest.mark.parametrize(
    "profile",
    [
        "claude-code-ordinary-observation-v1",
        "cursor-ordinary-observation-v1",
    ],
)
def test_reused_native_evidence_survives_mixed_digest_and_item_limits(profile: str) -> None:
    """Issue #618: linking native evidence must not turn a union of item gaps into no content."""
    case, captured, scope = _captured_case_values(b"synthetic matching native evidence")
    native = case.projection.evidence[evd(1)].payload
    assert native is not None and native.digest_binding is not None
    digest_only = replace(
        native,
        evidence_id=evd(2),
        captured_object_id=None,
        strength=EvidenceImmutability.CONTENT_DIGEST,
        description="Digest-only synthetic item",
        digest_binding=replace(
            native.digest_binding,
            content_availability=EvidenceContentAvailability.DIGEST_ONLY,
            provenance=EvidenceDigestProvenance.CALLER_ASSERTED,
        ),
    )
    oversized = replace(digest_only, evidence_id=evd(3), description="x" * 5000)
    claims = {
        key: record(
            replace(row.payload, supporting_refs=(evd(1), evd(2), evd(3))), row.source_frontier
        )
        for key, row in case.projection.claims.items()
        if row.payload is not None
    }
    mixed = make_case(
        plans=case.projection.plans,
        obligations=case.projection.obligations,
        claims=claims,
        evidence={
            evd(1): case.projection.evidence[evd(1)],
            evd(2): evidence_record(digest_only, 5),
            evd(3): evidence_record(oversized, 6),
        },
        extra_refs=(clm(1), obl(1), evd(1), evd(2), evd(3)),
    )
    semantic = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=mixed,
        dependency_digest="sha256:" + "b" * 64,
        findings=_findings_for(mixed),
        review_context_profile=ReviewContextProfile.ASSISTED,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.ASSISTED),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        captured_content=(replace(captured, capture_profile=profile),),
        captured_content_scope=replace(scope, authorized_profiles=(profile,)),
    )
    native_excerpt = next(item for item in semantic.items if item.item_id == f"excerpt-{evd(1)}")
    assert native_excerpt.content == captured.content
    large_excerpt = next(item for item in semantic.items if item.item_id == f"excerpt-{evd(3)}")
    # The approved per-excerpt bound (16 KiB) carries the 5,000-byte description whole (#907).
    assert oversized.description is not None
    assert large_excerpt.content == oversized.description.encode("utf-8")
    prepared = semantic_case_to_prepared_payload(
        semantic, {item.item_id for item in semantic.items}
    )
    assert b"synthetic matching native evidence" in prepared


def test_unreserved_excerpts_compete_by_recency_before_link_class() -> None:
    """Outside the reserved room, newer material wins the last slot (issue #907, step 3.4).

    Link class used to outrank recency, so an old claim-linked metadata row beat newer captured
    output. The reserved-room order ranks everything unreserved by recency, then by link class.
    """

    case, captured, scope, captured_ref = _opaque_before_capture_case()
    row = case.projection.claims[clm(1)]
    assert row.payload is not None
    case = replace(
        case,
        projection=replace(
            case.projection,
            claims={
                clm(1): claim_record(
                    replace(row.payload, supporting_refs=(evd(1),)), row.source_frontier
                )
            },
        ),
    )
    selection = replace(
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED), max_excerpts=1
    )
    semantic = _build(
        case,
        ReviewContextProfile.EXPANDED,
        captured_content=(captured,),
        captured_content_scope=scope,
        selection=selection,
    )
    assert semantic.packet.targeted_excerpts[0].excerpt_item_id == f"excerpt-{captured_ref}"
    assert any(
        omission.subject_ref == str(evd(1)) and omission.reason == "not_selected"
        for omission in semantic.packet.omissions
    )


def test_retained_code_hunks_beyond_first_item_reach_prepared_review() -> None:
    content = ("+ordinary_line()\n" * 1_100 + "+planted_late_bug()\n").encode()
    case, captured, scope = _captured_case_values(content)
    captured = replace(
        captured,
        manifest=replace(captured.manifest, content_kind=ObservationContentKind.WORKSPACE_DIFF),
    )
    semantic = _build(
        case,
        ReviewContextProfile.EXPANDED,
        captured_content=(captured,),
        captured_content_scope=scope,
    )
    excerpts = [item for item in semantic.items if item.section == "excerpt"]
    assert len(excerpts) > 1
    # Each part honors the approved per-excerpt bound; a part is one slot of one capture.
    assert all(item.content_bytes <= 16_384 for item in excerpts)
    assert b"".join(item.content for item in excerpts) == content
    prepared = semantic_case_to_prepared_payload(
        semantic, {item.item_id for item in semantic.items}
    )
    assert b"planted_late_bug" in prepared
    assert "truncated_payload" not in semantic.packet.coverage.known_gaps


@pytest.mark.parametrize("max_excerpts, max_total", [(1, 65536), (16, 4096)])
def test_code_chunk_selection_keeps_utf8_and_reports_unselected_suffix(
    max_excerpts: int, max_total: int
) -> None:
    content = ("+π🙂\n" * 4_000).encode()
    case, captured, scope = _captured_case_values(content)
    captured = replace(
        captured,
        manifest=replace(captured.manifest, content_kind=ObservationContentKind.WORKSPACE_DIFF),
    )
    selection = replace(
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED),
        max_excerpts=max_excerpts,
        max_total_excerpt_bytes=max_total,
    )
    semantic = _build(
        case,
        ReviewContextProfile.EXPANDED,
        captured_content=(captured,),
        captured_content_scope=scope,
        selection=selection,
    )
    excerpts = [item for item in semantic.items if item.section == "excerpt"]
    delivered = b"".join(item.content for item in excerpts)
    assert delivered and content.startswith(delivered) and delivered != content
    assert len(delivered) <= max_total
    assert len(excerpts) <= max_excerpts
    delivered.decode("utf-8")
    assert {"truncated_payload", "content_unselected"}.issubset(semantic.packet.coverage.known_gaps)
    manifest = semantic.packet.input_manifest
    assert manifest is not None
    assert manifest.current_diff.status == "partial"
    assert "truncated_payload" in manifest.current_diff.omission_reasons


def _routine_case() -> DeterministicCase:
    """The same plan and open obligation as ``_case_with_material`` with no completion claim."""

    base = _case_with_material(with_evidence=False)
    return make_case(
        plans=base.projection.plans,
        obligations=base.projection.obligations,
        extra_refs=(obl(1),),
    )


def test_question_set_names_the_phase_the_budget_selector_picks() -> None:
    """Issue #906: routine work is not judged as a completion claim, and vice versa."""

    final_case = _case_with_material()
    routine_case = _routine_case()
    assert select_semantic_budget_profile(final_case.projection) == "final"
    assert select_semantic_budget_profile(routine_case.projection) == "routine"

    cases: tuple[tuple[DeterministicCase, SemanticBudgetProfile], ...] = (
        (final_case, "final"),
        (routine_case, "routine"),
    )
    for case, phase in cases:
        semantic = _build(case, ReviewContextProfile.GOAL_AWARE)
        assert semantic.question_set == review_question_set(phase)
        assert semantic.question_set[0] == REVIEW_PHASE_QUESTIONS[phase]
        assert semantic.question_set[0].startswith(f"Review phase: {phase}. ")
        document = cast(
            Mapping[str, JsonValue],
            strict_json_parse(
                semantic_case_to_prepared_payload(
                    semantic, {item.item_id for item in semantic.items}
                )
            ),
        )
        # The reviewer reads the phase in the packet it is sent.
        assert document["question_set"] == list(review_question_set(phase))

    final = _build(final_case, ReviewContextProfile.GOAL_AWARE)
    routine = _build(routine_case, ReviewContextProfile.GOAL_AWARE)
    assert final.question_set[1:] == routine.question_set[1:]
    # The phase is bound into the case digest like the rest of the question set.
    assert final.case_digest != routine.case_digest


def test_no_review_question_presupposes_a_defect_or_hands_back_the_next_step() -> None:
    phases: tuple[SemanticBudgetProfile, ...] = ("routine", "final")
    for phase in phases:
        questions = review_question_set(phase)
        assert len(questions) == len(set(questions))
        joined = " ".join(questions)
        assert "smallest next step" not in joined
        assert "next step" not in joined
        assert "If so" not in joined
        assert "What did you verify against the task and the change, and with what result?" in (
            questions
        )
        assert any("if any" in question for question in questions)
    with pytest.raises(ValueError, match="semantic_budget_profile_invalid"):
        review_question_set(cast(SemanticBudgetProfile, "completion"))


def test_recorded_history_packet_keeps_process_rows_and_the_final_phase() -> None:
    """dateutil shape: earlier check and finding rows sit beside a completion claim.

    The reviewer still sees Yoetz's own check/finding rows (they are history, and a response to a
    finding stays reviewable); the instruction, not a packet filter, tells it they are process
    state. The recorded replay vector supplies real event shapes rather than normalized envelopes.
    """

    records = replay_records("all-event-families")
    case = build_deterministic_case(replay(records), records, CaseAvailabilityFacts())
    semantic = _build(case, ReviewContextProfile.GOAL_AWARE)
    phase = select_semantic_budget_profile(case.projection)
    assert semantic.question_set == review_question_set(phase)
    kinds: set[str] = set()
    for item in semantic.items:
        if item.item_id in semantic.packet.timeline_item_ids and item.item_id.startswith(
            "history-"
        ):
            document = strict_json_parse(item.content)
            assert isinstance(document, Mapping)
            kinds.add(cast(str, cast(Mapping[str, JsonValue], document)["kind"]))
    assert {"check_recorded", "finding_recorded", "response_recorded"} <= kinds
