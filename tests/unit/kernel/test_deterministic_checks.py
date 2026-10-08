"""Local case construction, rendering, and dispatch conformance."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import replace
from types import MappingProxyType
from typing import Any, cast

import pytest

from builders.policy_cases import clm, evt, make_case, obl, plan_record, record
from builders.replay import replay_records
from yoetz.domain.events import (
    AcceptedEvent,
    ClaimKind,
    ClaimRecordedPayload,
    NoObligationsReason,
    PlanPublishedPayload,
    accepted_record_digest_preimage,
    encode_payload,
)
from yoetz.domain.findings import FINDING_KIND_TRAITS, Finding, FindingKind, FindingOrigin
from yoetz.domain.receipts import (
    COMPLETION_CLAIM_OUTSIDE_PLAN_GAP,
    COMPLETION_SCOPE_DECLARED_NONE_GAP,
    COMPLETION_SCOPE_UNDECLARED_GAP,
)
from yoetz.domain.values import (
    Frontier,
    claim_id,
    event_id,
    finding_id,
    object_id,
    obligation_id,
    result_id,
)
from yoetz.kernel import deterministic_checks
from yoetz.kernel.deterministic_checks import (
    DETERMINISTIC_FINDING_TEMPLATES,
    DETERMINISTIC_TEXT_CONTRACT_DIGEST,
    CaseAvailabilityFacts,
    FindingFact,
    PolicyPack,
    UnavailableCapturedObject,
    build_deterministic_case,
    deterministic_case_from_json,
    deterministic_case_to_json,
    finding_basis_from_json,
    finding_basis_to_json,
    finding_basis_to_status_json,
    render_deterministic_finding_text,
    run_deterministic_policies,
)
from yoetz.kernel.policies.research_evidence import RESEARCH_EVIDENCE_POLICY_PACK
from yoetz.kernel.policies.work_integrity import WORK_INTEGRITY_POLICY_PACK
from yoetz.kernel.projections import empty_projection_state
from yoetz.kernel.reducers import replay
from yoetz.protocol.canonical import (
    canonical_digest,
    canonical_encode,
    entry_digest,
    strict_json_parse,
)
from yoetz.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)


def test_genesis_case_is_exact_and_immutable() -> None:
    case = build_deterministic_case(
        empty_projection_state(),
        (),
        CaseAvailabilityFacts(),
    )
    assert case.frontier.sequence == 0
    assert case.frontier.head_digest == "genesis"
    assert case.allowed_ids == frozenset()
    assert case.coverage_by_ref == MappingProxyType({})
    assert case.gaps == ()
    with pytest.raises(TypeError):
        case.coverage_by_ref["evt_00000000-0000-4000-8000-000000000001"] = None  # type: ignore[index, assignment]


def test_completion_scope_case_gap_distinguishes_undeclared_declared_none_and_unknown() -> None:
    claim = ClaimRecordedPayload(clm(1), ClaimKind.COMPLETION, "Complete", (), obligation_refs=())
    empty_plan = PlanPublishedPayload(1, "Atomic scope", (), ())
    undeclared = make_case(
        plans={1: plan_record(empty_plan, 1)},
        claims={clm(1): record(claim, 2)},
    )
    gap = deterministic_checks.completion_scope_gap(undeclared.projection)
    assert gap is not None
    assert gap.code == COMPLETION_SCOPE_UNDECLARED_GAP
    assert gap.marker == f"{COMPLETION_SCOPE_UNDECLARED_GAP}:{evt(1)}"
    assert gap.subject_refs == ()

    for reason in NoObligationsReason:
        declared_plan = replace(empty_plan, no_obligations_reason=reason)
        declared = make_case(
            plans={1: plan_record(declared_plan, 1)},
            claims={clm(1): record(claim, 2)},
        )
        declared_gap = deterministic_checks.completion_scope_gap(declared.projection)
        assert declared_gap is not None
        assert declared_gap.code == COMPLETION_SCOPE_DECLARED_NONE_GAP

    no_plan = make_case(claims={clm(1): record(claim, 2)})
    assert deterministic_checks.completion_scope_gap(no_plan.projection) is None

    redacted_plan = replace(plan_record(empty_plan, 1), payload=None, redacted=True)
    unreadable = make_case(
        plans={1: redacted_plan},
        claims={clm(1): record(claim, 2)},
    )
    assert deterministic_checks.completion_scope_gap(unreadable.projection) is None

    declared_positive = make_case(
        plans={1: plan_record(PlanPublishedPayload(1, "Declared", (obl(1),), ()), 1)},
        claims={clm(1): record(claim, 2)},
    )
    assert deterministic_checks.completion_scope_gap(declared_positive.projection) is None


def test_deterministic_case_codec_round_trips_canonical_bytes() -> None:
    records = replay_records("all-event-families")
    case = build_deterministic_case(replay(records), records, CaseAvailabilityFacts())
    encoded = deterministic_case_to_json(case)
    decoded = deterministic_case_from_json(encoded)
    assert decoded == case
    assert canonical_encode(deterministic_case_to_json(decoded)) == canonical_encode(encoded)


def test_legacy_digest_gap_is_scoped_to_evidence_linked_by_current_work() -> None:
    records = replay_records("all-event-families")
    unlinked = records[:8]
    unlinked_case = build_deterministic_case(replay(unlinked), unlinked, CaseAvailabilityFacts())
    assert not any(
        gap.code == "evidence_digest_subject_legacy_unknown" for gap in unlinked_case.gaps
    )

    linked = records[:9]
    linked_case = build_deterministic_case(replay(linked), linked, CaseAvailabilityFacts())
    gap = next(
        item for item in linked_case.gaps if item.code == "evidence_digest_subject_legacy_unknown"
    )
    evidence = next(iter(linked_case.projection.evidence.values()))
    assert gap.subject_refs == (evidence.source_event_id,)
    coverage = linked_case.coverage_by_ref[next(iter(linked_case.projection.evidence))]
    assert "evidence_digest_subject_legacy_unknown" in coverage.known_gaps


def test_frozen_history_is_bounded_and_legacy_cases_remain_distinct(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = replay_records("all-event-families")
    projection = replay(records)
    monkeypatch.setattr(deterministic_checks, "MAX_FROZEN_HISTORY_EVENTS", 2)
    case = build_deterministic_case(projection, records, CaseAvailabilityFacts())
    assert [item.schema_name for item in case.history] == [
        "response_recorded",
        "plan_revised",
    ]
    assert case.history_omitted_before_count == 9
    encoded = deterministic_case_to_json(case)
    legacy = dict(encoded)
    legacy.pop("history")
    legacy.pop("history_availability")
    legacy.pop("history_omitted_before_count")
    # Cases frozen before history existed also predate the task context (issue #908).
    legacy.pop("task_context")
    decoded = deterministic_case_from_json(legacy)
    assert decoded.history == ()
    assert decoded.history_availability == "not_recorded"

    legacy_history = cast(dict[str, Any], strict_json_parse(canonical_encode(encoded)))
    for item in cast(list[dict[str, Any]], legacy_history["history"]):
        item.pop("accepted_at")
        item.pop("occurred_at_consistency")
    decoded_history = deterministic_case_from_json(legacy_history)
    assert decoded_history.history
    assert all(item.accepted_at is None for item in decoded_history.history)
    assert deterministic_case_from_json(deterministic_case_to_json(decoded_history)) == (
        decoded_history
    )


def test_frozen_history_payload_budget_marks_content_not_selected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = replay_records("all-event-families")
    monkeypatch.setattr(deterministic_checks, "MAX_FROZEN_HISTORY_BYTES", 1)
    case = build_deterministic_case(replay(records), records, CaseAvailabilityFacts())
    assert case.history
    assert all(item.payload is None for item in case.history)
    assert {item.content_visibility for item in case.history} == {"not_selected"}


def test_deterministic_case_decoder_rejects_extra_and_contradictory_state() -> None:
    records = replay_records("all-event-families")
    encoded = cast(
        dict[str, Any],
        strict_json_parse(
            canonical_encode(
                deterministic_case_to_json(
                    build_deterministic_case(replay(records), records, CaseAvailabilityFacts())
                )
            )
        ),
    )
    with_extra = deepcopy(encoded)
    with_extra["unexpected"] = None
    with pytest.raises(ValueError, match="deterministic_case_invalid"):
        deterministic_case_from_json(with_extra)

    missing_coverage = deepcopy(encoded)
    coverage = cast(dict[str, Any], missing_coverage["coverage_by_ref"])
    coverage.pop(next(iter(coverage)))
    with pytest.raises(ValueError, match="deterministic_case_invalid"):
        deterministic_case_from_json(missing_coverage)

    duplicate_allowed = deepcopy(encoded)
    allowed_ids = cast(list[Any], duplicate_allowed["allowed_ids"])
    allowed_ids.append(allowed_ids[0])
    with pytest.raises(ValueError, match="deterministic_case_invalid"):
        deterministic_case_from_json(duplicate_allowed)

    wrong_frontier = deepcopy(encoded)
    wrong_frontier["frontier"] = {
        "sequence": "0",
        "head_digest": "genesis",
    }
    with pytest.raises(ValueError, match="deterministic_case_invalid"):
        deterministic_case_from_json(wrong_frontier)


def test_case_requires_the_exact_projection_prefix_head_pair() -> None:
    records = replay_records("all-event-families")
    projection = replay(records[:-1])
    with pytest.raises(ValueError, match="deterministic_case_invalid"):
        build_deterministic_case(projection, records, CaseAvailabilityFacts())


def test_replay_redaction_gaps_keep_typed_roots_and_caps() -> None:
    records = replay_records("all-event-families")
    case = build_deterministic_case(replay(records), records, CaseAvailabilityFacts())
    gaps = {(gap.code, gap.subject_refs) for gap in case.gaps}
    assert gaps == {
        # The fixture deliberately waives the only current plan obligation after recording a
        # completion claim. The claim remains effective, so ADR-019 requires this relation gap.
        (
            COMPLETION_CLAIM_OUTSIDE_PLAN_GAP,
            (),
        ),
        (
            COMPLETION_SCOPE_UNDECLARED_GAP,
            (),
        ),
        (
            "redacted_event",
            ("evt_20000002-0000-4000-8000-000000000008",),
        ),
        (
            "redacted_object",
            ("evt_20000002-0000-4000-8000-00000000000e",),
        ),
    }
    evidence = case.coverage_by_ref[next(iter(case.projection.evidence))]
    assert evidence.artifact_observation.value == "published_only"
    assert evidence.evidence_immutability.value == "metadata_only"
    assert evidence.ledger_freshness.value == "redacted_gap"
    assert evidence.known_gaps == ("redacted_event", "redacted_object")


def test_event_payload_unavailability_is_explicit_and_exact() -> None:
    records = replay_records("all-event-families")[:2]
    obligation = records[1]
    assert type(obligation) is AcceptedEvent
    unavailable_record = replace(obligation, payload=None)
    unavailable_prefix = (records[0], unavailable_record)
    projection = replay(unavailable_prefix)
    with pytest.raises(ValueError, match="deterministic_case_invalid"):
        build_deterministic_case(projection, unavailable_prefix, CaseAvailabilityFacts())

    facts = CaseAvailabilityFacts((unavailable_record.event_id,), ())
    case = build_deterministic_case(projection, unavailable_prefix, facts)
    assert case.gaps[-1].code == "event_payload_unavailable"
    obligation_id = next(iter(projection.obligations))
    coverage = case.coverage_by_ref[obligation_id]
    assert coverage.known_gaps == ("event_payload_unavailable",)
    assert coverage.artifact_observation.value == "published_only"
    assert coverage.ledger_freshness.value == "redacted_gap"


def test_captured_object_unavailability_requires_current_exact_association() -> None:
    records = replay_records("all-event-families")[:8]
    projection = replay(records)
    evidence = next(iter(projection.evidence.values()))
    assert evidence.payload is not None
    captured = evidence.payload.captured_object_id
    assert captured is not None
    facts = CaseAvailabilityFacts(
        (),
        (UnavailableCapturedObject(evidence.source_event_id, captured),),
    )
    case = build_deterministic_case(projection, records, facts)
    evidence_id = evidence.payload.evidence_id
    assert case.coverage_by_ref[evidence_id].known_gaps == ("captured_object_unavailable",)
    bad = CaseAvailabilityFacts(
        (),
        (
            UnavailableCapturedObject(
                evidence.source_event_id,
                object_id("obj_00000000-0000-4000-8000-000000000999"),
            ),
        ),
    )
    with pytest.raises(ValueError, match="deterministic_case_invalid"):
        build_deterministic_case(projection, records, bad)


def test_templates_are_complete_exact_and_structural() -> None:
    assert frozenset(DETERMINISTIC_FINDING_TEMPLATES) == frozenset(FindingKind)
    assert len(DETERMINISTIC_FINDING_TEMPLATES) == len(FindingKind)
    refs = (
        claim_id("clm_00000000-0000-4000-8000-000000000001"),
        obligation_id("obl_00000000-0000-4000-8000-000000000001"),
    )
    assert render_deterministic_finding_text(
        FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
        refs,
    ) == (
        "A completion claim covers an obligation that remains open.",
        "Subjects: clm_00000000-0000-4000-8000-000000000001, "
        "obl_00000000-0000-4000-8000-000000000001. Main agent: "
        "Resolve the obligation or revise the completion claim. An obligation you acknowledged"
        " as not done is not completed: omit it from the completion claim (replace the claim"
        " with claim_recorded/1.1.0 supersedes_claim_refs); the receipt discloses it as not"
        " done, and omitting it is not a plan-scope gap.",
    )


def test_text_contract_digest_pins_every_rendered_wording_branch() -> None:
    corpus = deterministic_checks._text_contract_corpus()  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    assert canonical_digest(corpus) == DETERMINISTIC_TEXT_CONTRACT_DIGEST
    assert len(corpus) == len(FindingKind) + 10
    rendered = canonical_encode(corpus).decode("utf-8")
    assert "No obligation in the current plan cites the recorded task statement." in rendered
    assert "plan declares no obligation for the recorded task statement" in rendered
    assert "yoetz-no-material-work:evt_" in rendered
    assert "publish a NEW obligation_published" in rendered
    assert "cites no verification made after the latest observed edit" in rendered
    assert "self-generated evidence is admissible" in rendered
    assert "Observed run: result res_" in rendered
    assert "Gaps: missing_ref." in rendered
    assert "Evidence provenance is recorded history" in rendered
    assert "an acknowledgement answers this finding but does not resolve it" in rendered
    assert "content-bearing" not in rendered
    assert "limiting result res_" in rendered
    assert "material coverage-gap record evt_" in rendered
    assert "task-level material coverage gap" in rendered


def test_text_contract_digest_tracks_template_wording(monkeypatch: pytest.MonkeyPatch) -> None:
    reworded = dict(DETERMINISTIC_FINDING_TEMPLATES)
    template = reworded[FindingKind.ACTION_WITHOUT_RESULT]
    reworded[FindingKind.ACTION_WITHOUT_RESULT] = replace(
        template, summary=template.summary + " (reworded)"
    )
    monkeypatch.setattr(
        deterministic_checks,
        "DETERMINISTIC_FINDING_TEMPLATES",
        MappingProxyType(reworded),
    )
    reworded_digest = canonical_digest(
        deterministic_checks._text_contract_corpus()  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    )
    assert reworded_digest != DETERMINISTIC_TEXT_CONTRACT_DIGEST


def test_material_limitation_detail_names_the_safe_limiting_record() -> None:
    claim = claim_id("clm_00000000-0000-4000-8000-000000000001")
    result = result_id("res_00000000-0000-4000-8000-000000000002")
    _, detail = render_deterministic_finding_text(
        FindingKind.MATERIAL_LIMITATION_OMITTED,
        (claim,),
        observed_facts=(FindingFact("material_limitation_present", (claim, result)),),
    )
    assert (
        "Omitted limitation basis: limiting result res_00000000-0000-4000-8000-000000000002."
    ) in detail


def test_rootless_material_limitation_detail_does_not_invent_a_record() -> None:
    claim = claim_id("clm_00000000-0000-4000-8000-000000000001")
    _, detail = render_deterministic_finding_text(
        FindingKind.MATERIAL_LIMITATION_OMITTED,
        (claim,),
        observed_facts=(FindingFact("material_limitation_present", (claim,)),),
    )
    assert "task-level material coverage gap" in detail
    assert "no individual limitation record was available" in detail


def test_dispatch_is_assessments_only_ordered_and_origin_deterministic() -> None:
    records = replay_records("all-event-families")
    case = build_deterministic_case(replay(records), records, CaseAvailabilityFacts())
    work = run_deterministic_policies(case, WORK_INTEGRITY_POLICY_PACK)
    assert len(work.assessments) == 1
    assessment = work.assessments[0]
    assert assessment.candidate.kind is FindingKind.LEDGER_STALE_OR_INCOMPLETE
    assert assessment.candidate.origin is FindingOrigin.DETERMINISTIC
    assert assessment.candidate.provenance is None
    assert not hasattr(work, "outcome")
    assert (
        run_deterministic_policies(
            case,
            RESEARCH_EVIDENCE_POLICY_PACK,
        ).assessments
        == ()
    )


def test_status_basis_projection_is_controlled_and_exact() -> None:
    records = replay_records("all-event-families")
    case = build_deterministic_case(replay(records), records, CaseAvailabilityFacts())
    assessment = run_deterministic_policies(
        case,
        WORK_INTEGRITY_POLICY_PACK,
    ).assessments[0]
    projected = finding_basis_to_status_json(assessment)
    assert projected["rule_id"] == "ledger_stale_or_incomplete"
    assert projected["observed_fact_codes"] == ["redaction_gap_present"]
    assert projected["frozen_source_availability"] == "redacted"
    assert projected["subject_state_relation"] == "unknown"
    assert projected["evidence_refs"] == []
    assert "supporting_refs" not in projected


def test_finding_basis_codec_is_lossless_closed_and_distinct_from_status() -> None:
    records = replay_records("all-event-families")
    case = build_deterministic_case(replay(records), records, CaseAvailabilityFacts())
    assessment = run_deterministic_policies(case, WORK_INTEGRITY_POLICY_PACK).assessments[0]
    encoded = finding_basis_to_json(assessment.basis)
    assert finding_basis_from_json(encoded) == assessment.basis
    assert canonical_encode(finding_basis_to_json(finding_basis_from_json(encoded))) == (
        canonical_encode(encoded)
    )

    with_extra = deepcopy(encoded)
    cast(dict[str, Any], with_extra)["unexpected"] = None
    with pytest.raises(ValueError, match="finding_basis_invalid"):
        finding_basis_from_json(with_extra)
    with pytest.raises(ValueError, match="finding_basis_invalid"):
        finding_basis_from_json(cast(Any, finding_basis_to_status_json(assessment)))


def test_unknown_or_tampered_pack_is_rejected() -> None:
    case = build_deterministic_case(
        empty_projection_state(),
        (),
        CaseAvailabilityFacts(),
    )
    with pytest.raises(ValueError, match="policy_wiring_invalid"):
        run_deterministic_policies(case, PolicyPack("work-integrity", "0.1.1"))


def _observation_finding_coverage() -> Coverage:
    return Coverage(
        publication_channels=(PublicationChannel.ENGINE_DERIVED,),
        authorship_assurance=AuthorshipAssurance.HARNESS_OBSERVED,
        artifact_observation=ArtifactObservation.HOOK_OBSERVED,
        evidence_immutability=EvidenceImmutability.METADATA_ONLY,
        ledger_freshness=LedgerFreshness.CURRENT,
        check_types=(CheckType.DETERMINISTIC,),
        known_gaps=(),
    )


def _observation_finding(*, number: int, subject_refs: tuple[str, ...]) -> Finding:
    kind = FindingKind.FAILED_WORK_OMITTED
    return Finding(
        finding_id(f"fnd_30000000-0000-4000-8000-{number:012x}"),
        kind,
        FindingOrigin.DETERMINISTIC,
        FINDING_KIND_TRAITS[kind][0],
        "A failed command remains unresolved.",
        "Resolve the failed command and rerun the check.",
        tuple(
            event_id(ref) if ref.startswith("evt_") else obligation_id(ref)
            for ref in sorted(subject_refs)
        ),
        "work-integrity",
        "0.1.0",
        Frontier(1, "sha256:" + "b" * 64),
        _observation_finding_coverage(),
        None,
    )


def _append_finding_record(
    prefix: tuple[Any, ...],
    finding: Finding,
    *,
    number: int,
) -> tuple[Any, ...]:
    template = next(
        record
        for record in prefix
        if type(record) is AcceptedEvent and record.schema.name == "finding_recorded"
    )
    last = prefix[-1]
    assert type(last) is AcceptedEvent
    payload_digest = canonical_digest(encode_payload(finding))
    next_event = event_id(f"evt_30000000-0000-4000-8000-{number:012x}")
    next_object = object_id(f"obj_30000000-0000-4000-8000-{number:012x}")
    next_ledger = replace(
        last.ledger,
        ingestion_sequence=last.ledger.ingestion_sequence + 1,
        previous_entry_digest=last.entry_digest,
    )
    next_ref = replace(template.payload_ref, object_id=next_object)
    preimage: dict[str, Any] = dict(accepted_record_digest_preimage(template))
    raw_payload_ref = cast(Mapping[str, Any], preimage["payload_ref"])
    preimage["event_id"] = next_event
    preimage["payload_ref"] = {**raw_payload_ref, "object_id": next_object}
    preimage["ledger"] = {
        "ingestion_sequence": str(next_ledger.ingestion_sequence),
        "previous_entry_digest": next_ledger.previous_entry_digest,
        "accepted_at": next_ledger.accepted_at.wire,
    }
    record = replace(
        template,
        event_id=next_event,
        payload=finding,
        payload_ref=next_ref,
        ledger=next_ledger,
        entry_digest=entry_digest(cast(Any, preimage)),
        projection_locator=replace(
            template.projection_locator,
            logical_key=str(finding.finding_id),
            canonical_payload_digest=payload_digest,
        ),
    )
    return (*prefix, record)


def test_case_keeps_observation_finding_citations_outside_history_or_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Receipt/case construction must not crash on observation finding event citations.

    Two shapes appear together in the #253 dogfood ledger: citations of real early
    events that fall outside the frozen history window, and citations of computed
    observation draft IDs that were never appended.
    """

    base = replay_records("all-event-families")
    early = next(
        record
        for record in base
        if type(record) is AcceptedEvent
        and record.schema.name
        in {
            "action_recorded",
            "check_recorded",
            "claim_recorded",
            "decision_recorded",
            "evidence_recorded",
            "finding_recorded",
            "obligation_published",
            "plan_published",
            "plan_revised",
            "response_recorded",
            "result_recorded",
        }
    )
    phantom = event_id("evt_40000000-0000-4000-8000-0000000000aa")
    records = base
    for index in range(1, 81):
        cited = (str(early.event_id), str(event_id(f"evt_40000000-0000-4000-8000-{index:012x}")))
        records = _append_finding_record(
            records,
            _observation_finding(number=index, subject_refs=cited),
            number=index,
        )
    records = _append_finding_record(
        records,
        _observation_finding(number=81, subject_refs=(str(phantom),)),
        number=81,
    )

    monkeypatch.setattr(deterministic_checks, "MAX_FROZEN_HISTORY_EVENTS", 2)
    projection = replay(records)
    case = build_deterministic_case(projection, records, CaseAvailabilityFacts())

    assert early.event_id in case.allowed_ids
    assert early.event_id not in {item.event_id for item in case.history}
    assert phantom not in case.allowed_ids
    assert any(gap.code == "missing_ref" for gap in case.gaps)
    assert any(gap.marker == "missing_ref:cited_event_absent" for gap in case.gaps)
    assert len(case.projection.findings) >= 80
    assert case.history_omitted_before_count > 0
