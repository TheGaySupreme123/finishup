"""Explicit links, bounded dialogue and separate privacy admissions (#1205)."""

from __future__ import annotations

# pyright: reportPrivateUsage=false
import json
from dataclasses import fields, replace
from typing import Any, cast

import pytest

from builders.policy_cases import (
    act,
    clm,
    evt,
    finding_record,
    fnd,
    make_case,
    obl,
    obligation_record,
    record,
    res,
)
from builders.replay import genesis_session_opened, replay_records
from finishup.application.semantic_case import (
    build_semantic_case,
    semantic_case_packet_view,
    semantic_case_to_prepared_payload,
)
from finishup.domain.correctness_advisories import ADVISORY_RESPONSE_STATEMENT
from finishup.domain.events import (
    AcceptedEvent,
    ActionKind,
    ActionRecordedPayload,
    ClaimKind,
    ClaimRecordedPayload,
    DecisionRecordedPayload,
    EventPayload,
    EventSchema,
    LedgerRecord,
    ObligationPublishedPayload,
    ObligationStatus,
    ProjectionLocator,
    ResultOutcome,
    ResultRecordedPayload,
    ResultVerification,
    VerificationDataSource,
    accepted_record_digest_preimage,
    compute_entry_digest,
    encode_payload,
    media_type_for,
)
from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from finishup.domain.values import Actor, ActorType, JsonObject, actor_id, object_id
from finishup.kernel.deterministic_checks import (
    CaseAvailabilityFacts,
    build_deterministic_case,
    deterministic_case_from_json,
    deterministic_case_to_json,
)
from finishup.kernel.evidence_basis import (
    MAX_EVIDENCE_VIEW_BYTES,
    build_evidence_view,
    evidence_basis_by_obligation,
    evidence_view_json,
    evidence_view_refs,
)
from finishup.kernel.projections import (
    LatestTestedState,
    projection_from_snapshot,
    projection_snapshot,
)
from finishup.kernel.reducers import replay
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.protocol.coverage import AuthorshipAssurance, PublicationChannel
from finishup.protocol.models import DataCategory, classify_result_leaf
from unit.kernel import test_finding_resolution as resolution
from unit.kernel import test_self_verification as self_verify


def _envelope(
    sequence: int,
    family: str,
    payload: EventPayload,
    *,
    observed: bool = False,
    previous: LedgerRecord | None = None,
) -> AcceptedEvent:
    """Individually valid accepted records; tests that need a replay chain use real vectors."""
    base = genesis_session_opened()
    version = {
        "check_recorded": "1.3.0",
        "decision_recorded": "1.1.0",
        "result_recorded": "1.1.0",
    }.get(family, "1.0.0")
    if family == "check_recorded" and isinstance(payload, resolution.CheckRecordedPayload):
        version = (
            "1.6.0"
            if payload.correctness_advisories
            else "1.4.0"
            if payload.verified
            else "1.3.0"
            if payload.semantic_conclusion is not None
            else "1.2.0"
        )
    schema = EventSchema(family, version)
    logical = next(
        (
            getattr(payload, name)
            for name in ("obligation_id", "action_id", "claim_id")
            if hasattr(payload, name)
        ),
        None,
    )
    if family == "result_recorded":
        logical = cast(ResultRecordedPayload, payload).result_id
    if family in {"check_recorded", "decision_recorded"}:
        logical = evt(sequence)
    values: dict[str, Any] = {
        field.name: getattr(base, field.name) for field in fields(AcceptedEvent) if field.init
    }
    refs: tuple[str, ...] = ()
    parents: tuple[str, ...] = ()
    if isinstance(payload, DecisionRecordedPayload) and payload.advisory_response is not None:
        refs = cast(tuple[str, ...], payload.advisory_response["evidence_refs"])
        parents = (str(payload.advisory_response["advisory_id"]).split(":")[0],)
    if isinstance(payload, ResultRecordedPayload):
        refs = payload.evidence_refs
    values.update(
        event_id=evt(sequence),
        schema=schema,
        payload=payload,
        causal_parents=parents,
        evidence_refs=refs,
        ledger=replace(
            base.ledger,
            ingestion_sequence=sequence,
            previous_entry_digest=base.entry_digest if previous is None else previous.entry_digest,
        ),
        projection_locator=ProjectionLocator(
            schema, logical, canonical_digest(encode_payload(payload))
        ),
        payload_ref=replace(
            base.payload_ref,
            media_type=media_type_for(family),
            object_id=base.payload_ref.object_id
            if previous is None
            else object_id(f"obj_00000000-0000-4000-8000-{sequence:012d}"),
        ),
    )
    if observed:
        values.update(
            author=Actor(
                actor_id("yoetz:observation-coordinator"),
                ActorType.HARNESS,
                AuthorshipAssurance.HARNESS_OBSERVED,
            ),
            publication_channel=PublicationChannel.HOOK_OBSERVED,
            coverage=replace(
                base.coverage,
                publication_channels=(PublicationChannel.HOOK_OBSERVED,),
                authorship_assurance=AuthorshipAssurance.HARNESS_OBSERVED,
            ),
        )
    unchecked = object.__new__(AcceptedEvent)
    for field in fields(AcceptedEvent):
        object.__setattr__(unchecked, field.name, values.get(field.name, getattr(base, field.name)))
    values["entry_digest"] = compute_entry_digest(accepted_record_digest_preimage(unchecked))
    return AcceptedEvent(**values)


def _case(*, observed: bool = False, disposition: str = "addressed"):
    obligations = {
        obl(n): obligation_record(
            ObligationPublishedPayload(
                obl(n),
                f"Criterion {n}",
                "Record a discriminating result",
                ObligationStatus.RESOLVED if n == 2 else ObligationStatus.OPEN,
                resolution_evidence_refs=(res(1),) if n == 2 else (),
            ),
            n + 1,
        )
        for n in (1, 2, 3)
    }
    action = ActionRecordedPayload(
        act(1),
        ActionKind.COMMAND,
        "Run weak probe",
        obligation_refs=(obl(1), obl(2)),
        command="bun weak.js",
    )
    result = ResultRecordedPayload(
        res(1),
        act(1),
        ResultOutcome.SUCCESS,
        summary="WEAK_PROBE: unused canary can be optimized away",
        verification=ResultVerification(
            "Criterion 1", VerificationDataSource.OWN_GENERATED, 1, 0, tuned_on_these_cases=True
        ),
    )
    claim = ClaimRecordedPayload(
        clm(1), ClaimKind.MATERIAL, "The probe passed", (res(1),), obligation_refs=(obl(1),)
    )
    unscoped = ClaimRecordedPayload(
        clm(2), ClaimKind.MATERIAL, "General task assertion", (res(1),), obligation_refs=()
    )
    check = replace(
        resolution._check(semantic=resolution._SEMANTIC_OK),
        correctness_advisories=(
            JsonObject(
                {
                    "summary": "PROPOSAL: use a runtime discriminator",
                    "detail": "ADVICE_DETAIL: the canary must affect an observable outcome",
                    "subject_refs": (evt(10),),
                }
            ),
        ),
        verified=(
            JsonObject(
                {
                    "requirement_or_claim": "ASSESSMENT: weak probe does not distinguish outcomes",
                    "verdict": "not_supported",
                    "cited_refs": (obl(1),),
                    "snippet": "The probe passed",
                }
            ),
        ),
    )
    answer = DecisionRecordedPayload(
        ADVISORY_RESPONSE_STATEMENT,
        "RESPONSE_REASON: optional comparison declined; uncertainty remains"
        if disposition == "declined"
        else "RESPONSE_REASON: ran weak probe, not the proposed discriminator",
        actor_id("agent"),
        advisory_response=JsonObject(
            {
                "advisory_id": f"{evt(30)}:1",
                "disposition": disposition,
                "evidence_refs": () if disposition == "declined" else (res(1),),
            }
        ),
    )
    records: tuple[LedgerRecord, ...] = (
        _envelope(10, "action_recorded", action, observed=observed),
        _envelope(11, "result_recorded", result, observed=observed),
        _envelope(20, "claim_recorded", claim),
        _envelope(21, "claim_recorded", unscoped),
        _envelope(30, "check_recorded", check),
        _envelope(40, "decision_recorded", answer),
    )
    case = make_case(
        obligations=obligations,
        actions={act(1): record(action, 10)},
        results={res(1): record(result, 11)},
        claims={clm(1): record(claim, 20), clm(2): record(unscoped, 21)},
        extra_refs=(evt(30), evt(40)),
    )
    state = replace(
        case.projection,
        latest_tested_state=LatestTestedState(
            evt(30), check.subject_frontier, check.verdict, (), 0, check.coverage
        ),
    )
    return replace(case, projection=state), records


@pytest.mark.parametrize("observed", (False, True))
def test_explicit_many_to_many_links_separate_proposal_response_observation_and_assessment(
    observed: bool,
) -> None:
    case, records = _case(observed=observed)
    basis = evidence_basis_by_obligation(
        build_evidence_view(case.projection, records, freshness=(), tracked_runs=())
    )
    first, second, unrelated = (basis[str(obl(n))] for n in (1, 2, 3))
    assert [row.claim_ref for row in first.claims] == [clm(1)]
    assert second.claims == unrelated.claims == ()
    assert first.results[0].observed is observed
    assert second.results[0].result_ref == res(1)
    assert first.results[0].verification is not None
    assert first.results[0].verification.tuned_on_these_cases is True
    assert first.results[0].freshness == "legacy"
    assert bool(first.observed_refs) is observed
    assert unrelated.results == unrelated.advisories == unrelated.assessments == ()
    assert first.advisories[0].disposition == "addressed"
    assert "not the proposed discriminator" in str(first.advisories[0].reason)
    assert first.assessments[0].verdict == "not_supported"
    # An advisory response does not invalidate a check or become reviewer proof itself.
    assert first.assessments[0].applicability == "current"
    later = _envelope(
        60,
        "claim_recorded",
        ClaimRecordedPayload(
            clm(3), ClaimKind.MATERIAL, "Later material change", (), obligation_refs=()
        ),
    )
    changed = evidence_basis_by_obligation(
        build_evidence_view(case.projection, (*records, later), freshness=(), tracked_runs=())
    )
    assert changed[str(obl(1))].assessments[0].applicability == "historical"


def test_optional_decline_and_unscoped_advice_stay_history_without_new_work() -> None:
    case, records = _case(disposition="declined")
    view = build_evidence_view(case.projection, records, freshness=(), tracked_runs=())
    assert view.advisories[0].disposition == "declined"
    assert view.advisories[0].evidence_refs == ()
    assert "uncertainty remains" in str(view.advisories[0].reason)
    check = records[-2]
    payload = replace(
        cast(Any, check.payload),
        correctness_advisories=(
            JsonObject(
                {"summary": "General task note", "detail": "No scoped link", "subject_refs": ()}
            ),
        ),
    )
    task_view = build_evidence_view(
        case.projection,
        (*records[:-2], _envelope(30, "check_recorded", payload), records[-1]),
        freshness=(),
        tracked_runs=(),
    )
    assert task_view.advisories
    assert all(not row.basis.advisories for row in task_view.obligations)


def test_prefix_missing_redacted_and_display_caps_never_fabricate_links() -> None:
    case, records = _case(observed=True)
    before_answer = replace(case.projection, frontier=35)
    view = build_evidence_view(before_answer, records, freshness=(), tracked_runs=())
    assert view.advisories[0].disposition == "no_recorded_response"
    hidden = replace(
        case.projection,
        results={res(1): replace(case.projection.results[res(1)], redacted=True, payload=None)},
    )
    hidden_view = build_evidence_view(hidden, records, freshness=(), tracked_runs=())
    row = evidence_basis_by_obligation(hidden_view)[str(obl(1))]
    assert row.results == row.observed_refs == ()
    assert row.advisories[0].evidence_refs == () and row.advisories[0].omitted > 0
    assert row.omitted > 0
    claims = {
        clm(n): record(
            ClaimRecordedPayload(
                clm(n), ClaimKind.MATERIAL, "Bounded", (res(1),), obligation_refs=(obl(1),)
            ),
            50 + n,
        )
        for n in range(1, 20)
    }
    overflow = replace(case.projection, claims=claims)
    bounded = build_evidence_view(overflow, records, freshness=(), tracked_runs=())
    assert len(evidence_basis_by_obligation(bounded)[str(obl(1))].claims) == 8
    assert evidence_basis_by_obligation(bounded)[str(obl(1))].omitted >= 11
    assert len(canonical_encode(evidence_view_json(bounded))) <= MAX_EVIDENCE_VIEW_BYTES


def test_advice_and_reason_survive_empty_history_with_separate_provider_categories() -> None:
    case, records = _case()
    view = build_evidence_view(case.projection, records, freshness=(), tracked_runs=())
    frozen = replace(
        case,
        evidence_view=evidence_view_json(view),
        allowed_ids=case.allowed_ids | evidence_view_refs(view),
    )
    decoded = deterministic_case_from_json(deterministic_case_to_json(frozen))
    assert decoded.evidence_view == frozen.evidence_view and decoded.history == ()
    packet = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=decoded,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.ASSISTED,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.ASSISTED),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
    )
    by_category = {
        category: b"\n".join(item.content for item in packet.items if item.category is category)
        for category in DataCategory
    }
    assert b"ADVICE_DETAIL" in by_category[DataCategory.FINDING_SUMMARY]
    assert b"RESPONSE_REASON" in by_category[DataCategory.DECISION_EXCERPT]
    assert b"WEAK_PROBE" in by_category[DataCategory.COMMAND_METADATA]
    for category in (DataCategory.BOUNDED_STRUCTURAL_METADATA, DataCategory.OBLIGATION_TEXT):
        assert b"ADVICE_DETAIL" not in by_category[category]
        assert b"RESPONSE_REASON" not in by_category[category]
        assert b"ASSESSMENT" not in by_category[category]
    assert semantic_case_packet_view(packet).prior_finding_refs == frozenset()
    assert packet.frontier_refs == frozen.allowed_ids
    allowed_items = {
        item.item_id for item in packet.items if item.category is not DataCategory.DECISION_EXCERPT
    }
    provider_view = semantic_case_to_prepared_payload(packet, allowed_items)
    assert b"ADVICE_DETAIL" in provider_view and b"RESPONSE_REASON" not in provider_view
    # A structural-only reviewer gets identities/status, not either participant's prose.
    structural = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=decoded,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.STRUCTURAL,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
    )
    structural_bytes = semantic_case_to_prepared_payload(
        structural, {item.item_id for item in structural.items}
    )
    assert b"RESPONSE_REASON" not in structural_bytes and b"ADVICE_DETAIL" not in structural_bytes


def test_capped_evidence_view_matches_live_replay_after_projection_snapshot_round_trip() -> None:
    records: list[LedgerRecord] = [genesis_session_opened()]
    payloads: list[tuple[str, EventPayload]] = [
        (
            "obligation_published",
            ObligationPublishedPayload(
                obl(1), "Criterion", "Record results", ObligationStatus.OPEN
            ),
        )
    ]
    for n in range(9, 0, -1):
        payloads.extend(
            (
                (
                    "action_recorded",
                    ActionRecordedPayload(
                        act(n),
                        ActionKind.COMMAND,
                        "Probe",
                        obligation_refs=(obl(1),),
                        command="true",
                    ),
                ),
                ("result_recorded", ResultRecordedPayload(res(n), act(n), ResultOutcome.SUCCESS)),
                (
                    "claim_recorded",
                    ClaimRecordedPayload(
                        clm(n), ClaimKind.MATERIAL, "Reported", (res(n),), obligation_refs=(obl(1),)
                    ),
                ),
            )
        )
    for sequence, (family, payload) in enumerate(payloads, start=2):
        records.append(
            _envelope(
                sequence,
                family,
                payload,
                observed=family != "claim_recorded",
                previous=records[-1],
            )
        )
    prefix = tuple(records)
    live = replay(prefix)
    restored = projection_from_snapshot(projection_snapshot(live))
    assert tuple(live.results) == tuple(res(n) for n in range(9, 0, -1))
    assert tuple(restored.results) == tuple(res(n) for n in range(1, 10))
    live_view = build_evidence_view(live, prefix)
    assert build_evidence_view(restored, prefix) == live_view
    basis = evidence_basis_by_obligation(live_view)[str(obl(1))]
    assert tuple(row.result_ref for row in basis.results) == tuple(res(n) for n in range(1, 9))
    assert len(basis.claims) == len(basis.action_refs) == len(basis.observed_refs) == 8
    assert basis.omitted >= 3


@pytest.mark.parametrize("baseline_bytes", [3691, 4096])
def test_optional_basis_yields_to_intact_criterion_in_actual_semantic_packet(
    baseline_bytes: int,
) -> None:
    case, records = _case()
    original = case.projection.obligations[obl(1)]
    assert original.payload is not None
    empty = replace(original.payload, description="x")
    padding = baseline_bytes - len(canonical_encode(encode_payload(empty)))
    description = "a" * (padding // 2) + " CENTRAL REQUIREMENT MUST SURVIVE "
    description = description.ljust(padding + 1, "z")
    payload = replace(empty, description=description)
    assert len(canonical_encode(encode_payload(payload))) == baseline_bytes
    state = replace(
        case.projection,
        obligations={
            **case.projection.obligations,
            obl(1): obligation_record(payload, original.source_frontier),
        },
    )
    view = build_evidence_view(state, records, freshness=(), tracked_runs=())
    assert evidence_basis_by_obligation(view)[str(obl(1))].results
    frozen = replace(
        case,
        projection=state,
        evidence_view=evidence_view_json(view),
        allowed_ids=case.allowed_ids | evidence_view_refs(view),
    )
    packet = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=frozen,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.ASSISTED,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.ASSISTED),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
    )
    item = next(item for item in packet.items if item.item_id == f"obligation-{obl(1)}")
    content = json.loads(item.content)
    assert content["description"] == description
    assert item.content_bytes <= 4096
    if baseline_bytes == 3691:
        assert content["evidence_basis"] == {"availability": "not_selected", "omitted": 1}
    else:
        assert "evidence_basis" not in content
    assert any(
        omission.subject_ref == str(obl(1))
        and omission.category is DataCategory.BOUNDED_STRUCTURAL_METADATA
        and omission.reason == "not_selected"
        for omission in packet.packet.omissions
    )


def test_new_basis_retains_frontier_and_old_cases_keep_their_bytes() -> None:
    records = replay_records("all-event-families")
    frozen = build_deterministic_case(replay(records), records, CaseAvailabilityFacts())
    assert frozen.evidence_view is not None
    encoded = deterministic_case_to_json(frozen)
    assert deterministic_case_to_json(deterministic_case_from_json(encoded)) == encoded
    legacy = replace(frozen, evidence_view=None)
    legacy_bytes = canonical_encode(deterministic_case_to_json(legacy))
    assert (
        canonical_encode(
            deterministic_case_to_json(
                deterministic_case_from_json(deterministic_case_to_json(legacy))
            )
        )
        == legacy_bytes
    )
    case, notes = _case()
    view = evidence_view_json(
        build_evidence_view(case.projection, notes, freshness=(), tracked_runs=())
    )
    with pytest.raises(ValueError, match="deterministic_case_invalid"):
        replace(case, evidence_view=view, allowed_ids=frozenset())


@pytest.mark.parametrize(
    ("field", "category"),
    (
        ("summary", DataCategory.FINDING_SUMMARY),
        ("detail", DataCategory.FINDING_SUMMARY),
        ("reason", DataCategory.DECISION_EXCERPT),
    ),
)
def test_local_status_content_and_structural_links_have_exact_categories(
    field: str, category: DataCategory
) -> None:
    body = cast(
        dict[str, JsonValue],
        {
            "ok": True,
            "view": "obligations",
            "page": {
                "items": [
                    {
                        "evidence_basis": {
                            "advisories": [{field: "private", "advisory_id": f"{evt(30)}:1"}]
                        }
                    }
                ]
            },
        },
    )
    assert (
        classify_result_leaf("status", body, f"/page/items/0/evidence_basis/advisories/0/{field}")
        is category
    )
    assert (
        classify_result_leaf(
            "status", body, "/page/items/0/evidence_basis/advisories/0/advisory_id"
        )
        == "public_structural"
    )


def test_golden_basis_and_optional_witness_freshness_contract() -> None:
    import importlib.util
    from pathlib import Path

    from pydantic import ValidationError

    from finishup.protocol.models import (
        StatusObligationEvidenceModel,
        StatusVerificationWitnessModel,
    )

    spec = importlib.util.spec_from_file_location(
        "evidence_fixture_owner",
        Path(__file__).resolve().parents[3] / "scripts/generate_verification_coverage_fixture.py",
    )
    assert spec is not None and spec.loader is not None
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    vector = owner.evidence_basis_example()
    basis = StatusObligationEvidenceModel.model_validate(vector)
    assert basis.model_dump(mode="json", exclude_unset=True) == vector
    witness = {
        "result_id": str(res(1)),
        "action_id": str(act(1)),
        "data_source": "unknown",
        "cases": 1,
        "failing": 0,
        "stale": False,
    }
    for freshness in (None, "current", "unknown", "legacy"):
        row = witness if freshness is None else {**witness, "freshness": freshness}
        assert StatusVerificationWitnessModel.model_validate(row).stale is False
    with pytest.raises(ValidationError):
        StatusVerificationWitnessModel.model_validate({**witness, "freshness": "stale"})
    with pytest.raises(ValidationError):
        StatusVerificationWitnessModel.model_validate(
            {**witness, "freshness": "unknown", "stale": True}
        )


def test_memory_status_and_compact_delivery_share_the_bounded_detail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finishup.adapters.memory.ledger import _projection_items
    from finishup.cli.closure_gate import closure_gate_from_readiness
    from finishup.cli.render import render_closure_readiness_lines, render_human_check
    from finishup.domain.receipts import (
        SchemaVersionEntry,
        receipt_document_to_json,
        render_receipt_human,
    )
    from finishup.kernel.evidence_basis import evidence_basis_summary
    from finishup.mcp.summaries import summary_for_check
    from finishup.ports.ledger import ProjectionView
    from finishup.protocol.models import (
        CheckSuccessModel,
        CoverageModel,
        StatusClosureReadinessModel,
        StatusObligationItemModel,
    )
    from unit.kernel import test_receipt_builder as receipt_test
    from unit.mcp.test_tb4n3_summary_bounds import _check

    case, records = _case()
    items = _projection_items(
        ProjectionView.OBLIGATIONS,
        case.projection,
        records,
        task=str(records[0].task_id),
        session=str(records[0].session_id),
    )
    assert all(
        isinstance(row, StatusObligationItemModel) and row.evidence_basis is not None
        for row in items
    )
    assert cast(StatusObligationItemModel, items[1]).status == "resolved"
    summary = evidence_basis_summary(case.projection)
    readiness = StatusClosureReadinessModel.model_construct(
        state="action_required",
        agent_actionable=("obligations_open",),
        standing_limitations=(),
        acknowledged_not_done=(),
        acknowledged_not_done_count="0",
        evidence_basis_summary=summary,
        open_obligation_count="1",
        receipt_blocking_finding_count="0",
    )
    assert summary in render_closure_readiness_lines(readiness)  # TUI uses this same renderer.
    check = CheckSuccessModel.model_construct(
        verdict="no_issue_detected",
        semantic_status="not_requested",
        semantic_reason="deterministic_mode",
        findings=(),
        suppressed_count="0",
        coverage=CoverageModel.model_construct(known_gaps=()),
        closure_readiness=readiness,
    )
    assert summary in render_human_check(check)
    assert "status view=obligations" in summary_for_check(
        _check(closure_readiness={"evidence_basis_summary": summary})
    )
    gate = closure_gate_from_readiness(
        readiness,
        frontier_sequence="100",
        frontier_digest="sha256:" + "a" * 64,
        observation_pending=False,
    )
    assert gate is not None and "status view=obligations" in gate.text
    assert (
        closure_gate_from_readiness(
            readiness.model_copy(update={"state": "ready"}),
            frontier_sequence="100",
            frontier_digest="sha256:" + "a" * 64,
            observation_pending=False,
        )
        is None
    )
    versions = replace(
        receipt_test._versions(),
        schema_versions=(SchemaVersionEntry("receipts/receipt-document", "1.3.0"),),
    )
    monkeypatch.setattr(receipt_test, "_versions", lambda: versions)
    context = receipt_test._context(
        obligation=case.projection.obligations[obl(1)].payload,
        check=receipt_test._check(
            resolution.CheckVerdict.NO_ISSUE_DETECTED, receipt_test._coverage()
        ),
    )
    receipt = receipt_test._build(context)
    assert "status view=obligations" in str(receipt_document_to_json(receipt))
    assert all(
        "status view=obligations" in render_receipt_human(receipt, markdown=markdown)
        for markdown in (False, True)
    )


def test_resolution_detail_uses_existing_eligibility_and_keeps_terminal_items_unavailable() -> None:
    from finishup.domain.findings import FindingKind
    from finishup.kernel.self_verification import self_verification_evaluation

    case, _records = _case()
    finding = self_verify._finding(kind=FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED)
    state = replace(case.projection, findings={finding.finding_id: finding_record(finding, 4)})
    for gap in ("command_attempt_uncorroborated", "planned_verification_stale"):
        check = self_verify._check(gaps=(gap,))
        records = (_envelope(50, "check_recorded", check),)
        expected = self_verification_evaluation(state, finding.finding_id, records)
        basis = evidence_basis_by_obligation(
            build_evidence_view(state, records, freshness=(), tracked_runs=())
        )[str(obl(1))]
        detail = basis.resolution[0]
        assert detail.self_verified_available is (expected[0] is None)
        assert (detail.self_verified_refusal, detail.blocking_reasons) == expected
        assert detail.reviewer_verdict is None and detail.ruling_check_event_id is None
        terminal = replace(
            state,
            findings={
                finding.finding_id: replace(
                    state.findings[finding.finding_id], resolved_by_check_event_id=evt(50)
                )
            },
        )
        final = evidence_basis_by_obligation(
            build_evidence_view(terminal, records, freshness=(), tracked_runs=())
        )[str(obl(1))].resolution[0]
        assert (
            not final.self_verified_available and final.self_verified_refusal == "finding_terminal"
        )


@pytest.mark.parametrize("count", [1, 16])
def test_resolution_reason_contract_preserves_existing_scoped_overlap_ids(count: int) -> None:
    from jsonschema import Draft202012Validator
    from pydantic import TypeAdapter, ValidationError

    from finishup.protocol.models import EvidenceResolutionReasonWire

    reason = "command_relation_overlaps_obligation:" + ",".join(obl(n) for n in range(count))
    adapter: TypeAdapter[str] = TypeAdapter(EvidenceResolutionReasonWire)
    assert adapter.validate_python(reason) == reason
    validate = cast(Any, Draft202012Validator(adapter.json_schema())).validate
    validate(reason)
    for invalid in (
        reason + ",private/path",
        reason.replace("obl_", "res_"),
        reason + "," + ",".join(obl(n) for n in range(16)),
    ):
        with pytest.raises(ValidationError):
            adapter.validate_python(invalid)
    # The shared view must accept the reason that the production closure predicate emits.
    case, records = _case()
    finding = self_verify._finding()
    state = replace(case.projection, findings={finding.finding_id: finding_record(finding, 4)})
    check = self_verify._check(gaps=("observation_input_loss",))
    basis = evidence_basis_by_obligation(
        build_evidence_view(
            state, (*records, _envelope(50, "check_recorded", check)), freshness=(), tracked_runs=()
        )
    )[str(obl(1))]
    row = basis.resolution[0]
    decoded = type(row).model_validate(
        {**row.model_dump(), "reasons": (reason,), "blocking_reasons": (reason,)}
    )
    assert decoded.reasons == decoded.blocking_reasons == (reason,)


def test_original_obligation_event_advice_survives_a_later_resolution_revision() -> None:
    case, records = _case()
    original = case.projection.obligations[obl(1)].payload
    assert original is not None
    first = _envelope(2, "obligation_published", original)
    updated = replace(
        original, status=ObligationStatus.RESOLVED, resolution_evidence_refs=(res(1),)
    )
    revision = _envelope(80, "obligation_published", updated)
    check = cast(resolution.CheckRecordedPayload, records[-2].payload)
    note = JsonObject({**dict(check.correctness_advisories[0].items()), "subject_refs": (evt(2),)})
    records = (
        first,
        *records[:-2],
        _envelope(30, "check_recorded", replace(check, correctness_advisories=(note,))),
        records[-1],
        revision,
    )
    state = replace(
        case.projection,
        obligations={**case.projection.obligations, obl(1): obligation_record(updated, 80)},
    )
    row = evidence_basis_by_obligation(
        build_evidence_view(state, records, freshness=(), tracked_runs=())
    )[str(obl(1))]
    assert row.advisories[0].advisory_id == f"{evt(30)}:1"
    assert row.advisories[0].response_event_id == evt(40)


def test_resolution_inspection_bounds_evaluator_calls_before_reading_the_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finishup.kernel import finding_resolution

    case, records = _case()
    finding = self_verify._finding()
    findings = {
        fnd(n): finding_record(replace(finding, finding_id=fnd(n)), n) for n in range(1, 101)
    }
    state = replace(case.projection, findings=findings)
    calls: list[object] = []
    evaluate = finding_resolution.finding_resolution_attempt

    def counted(*args: Any, **kwargs: Any) -> Any:
        calls.append(args[1])
        return evaluate(*args, **kwargs)

    monkeypatch.setattr(finding_resolution, "finding_resolution_attempt", counted)
    basis = evidence_basis_by_obligation(
        build_evidence_view(state, records, freshness=(), tracked_runs=())
    )[str(obl(1))]
    assert len(calls) == len(basis.resolution) == 4
    assert calls == [fnd(n) for n in range(100, 96, -1)]
    assert basis.omitted >= 96
    assert state.findings == findings


def test_owned_schema_keeps_ids_and_witness_freshness_closed() -> None:
    import importlib.util
    import json
    import sys
    from pathlib import Path

    from jsonschema import Draft202012Validator, ValidationError

    root = Path(__file__).resolve().parents[3]
    spec = importlib.util.spec_from_file_location(
        "evidence_schema_owner", root / "scripts/generate_schemas.py"
    )
    assert spec is not None and spec.loader is not None
    owner = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = owner
    spec.loader.exec_module(owner)
    definitions = json.loads(
        (root / "schemas/operations/status-result-1.4.0.schema.json").read_text()
    )["$defs"]
    owner._add_evidence_basis_schema(definitions)
    schema = {"$defs": definitions, "$ref": "#/$defs/obligation_evidence_basis"}
    case, records = _case()
    basis = evidence_basis_by_obligation(
        build_evidence_view(case.projection, records, freshness=(), tracked_runs=())
    )[str(obl(1))].model_dump(mode="json", exclude_unset=True)
    validate_basis = cast(Any, Draft202012Validator(schema)).validate
    validate_basis(basis)
    with pytest.raises(ValidationError):
        validate_basis({**basis, "action_refs": ["private/path"]})
    witness = owner._verification_coverage_schema()["properties"]["criteria"]["items"][
        "properties"
    ]["witnesses"]["items"]
    row = {
        "result_id": str(res(1)),
        "action_id": str(act(1)),
        "data_source": "unknown",
        "cases": 1,
        "failing": 0,
        "stale": False,
    }
    validate_witness = cast(Any, Draft202012Validator(witness)).validate
    validate_witness(row)
    validate_witness({**row, "freshness": "unknown"})
    with pytest.raises(ValidationError):
        validate_witness({**row, "freshness": "unknown", "stale": True})
