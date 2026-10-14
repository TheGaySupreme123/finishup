"""What a reduced AI-powered review sent decides what it can resolve (issue #904, PR930-F1).

The check records only the frontier references whose own content item survived in the exact
packet sent to the reviewer: after envelope bounding and privacy minimization, never a mention,
a typed link or an omission row. These tests build a real semantic case, assemble the provider
document from a privacy-approved item set, and ask the resolution kernel what that document can
prove.
"""

from __future__ import annotations

from dataclasses import replace
from typing import cast

from builders.policy_cases import (
    act,
    clm,
    evd,
    evidence_record,
    evt,
    fnd,
    make_case,
    obl,
    obligation_record,
    plan_record,
    record,
    res,
)
from finishup.application.semantic_case import (
    REVIEW_PACKET_ITEM_ID,
    build_semantic_case,
    review_packet_content_refs,
    semantic_case_to_candidate_context,
    semantic_case_to_prepared_payload,
)
from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    CheckMode,
    CheckRecordedPayload,
    ClaimKind,
    ClaimRecordedPayload,
    EvidenceKind,
    EvidenceRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    PolicyVersion,
    ResponseRecordedPayload,
    ResultOutcome,
    ResultRecordedPayload,
)
from finishup.domain.findings import (
    FINDING_KIND_TRAITS,
    CheckVerdict,
    Finding,
    FindingKind,
    FindingOrigin,
    ResponseDisposition,
    SemanticDispatchKind,
    SemanticProvenance,
)
from finishup.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    ProviderBinding,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from finishup.domain.values import Frontier, timestamp_from_string
from finishup.kernel.deterministic_checks import DeterministicCase
from finishup.kernel.finding_resolution import resolution_blockers
from finishup.ports.semantic import SamplingParams, SemanticCase
from finishup.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)
from finishup.protocol.models import (
    CheckPolicyExecutionModel,
    CheckScopeModel,
    SemanticReason,
    SemanticStatus,
)

_DIGEST = "sha256:" + "1" * 64
_SCOPE_REDUCED = "semantic_reference_scope_reduced"
_OUTSIDE = ("finding_material_outside_reduced_review_scope", "coverage:" + _SCOPE_REDUCED)
_REPAIR = evd(7)
_SCOPE = AuthorizationScope(
    AuthorizationScopeKind.TASK,
    "ins_10000000-0000-4000-8000-000000000001",
    "hmac-sha256:" + "a" * 64,
    "tsk_10000000-0000-4000-8000-000000000001",
)
_BINDING = ProviderBinding("fireworks", "test-model", "chat-completions", "1", "external")


def _coverage(*gaps: str) -> Coverage:
    return Coverage(
        publication_channels=(PublicationChannel.ENGINE_DERIVED,),
        authorship_assurance=AuthorshipAssurance.SERVICE_AUTHENTICATED,
        artifact_observation=ArtifactObservation.PUBLISHED_ONLY,
        evidence_immutability=EvidenceImmutability.METADATA_ONLY,
        ledger_freshness=LedgerFreshness.PARTIAL,
        check_types=(CheckType.DETERMINISTIC, CheckType.SEMANTIC_MODEL_DERIVED),
        known_gaps=tuple(sorted(gaps, key=str.encode)),
    )


def _provenance() -> SemanticProvenance:
    return SemanticProvenance(
        provider="fake",
        endpoint_profile_id="fake",
        endpoint_profile_version="1.0.0",
        model="fake/model",
        sdk_version="1.0.0",
        prompt_digest=_DIGEST,
        schema_digest=_DIGEST,
        policy_digest=_DIGEST,
        privacy_policy_digest=_DIGEST,
        sampling_params=SamplingParams(128),
        latency_ms=1,
        semantic_attempt_id="att_00000000-0000-4000-8000-000000000001",
        dispatch_kind=SemanticDispatchKind.EXTERNAL,
        privacy_receipt_id="egr_00000000-0000-4000-8000-000000000001",
        status=SemanticStatus.SUCCEEDED,
        reason=SemanticReason.SEMANTIC_COMPLETED,
        provider_request_id="fake-1",
        egress_authorization_id="aut_00000000-0000-4000-8000-000000000001",
        request_commitment="hmac-sha256:" + "b" * 64,
    )


def _finding() -> Finding:
    """An AI-powered finding about the completion claim, raised under a reduced scope."""

    kind = FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE
    return Finding(
        finding_id=fnd(1),
        kind=kind,
        origin=FindingOrigin.SEMANTIC_MODEL_DERIVED,
        priority=FINDING_KIND_TRAITS[kind][0],
        summary="The completion claim has no readable support.",
        detail="Record the result that supports the claim.",
        subject_refs=(clm(1),),
        policy_id="work-integrity",
        policy_version="0.1.0",
        subject_frontier=Frontier(4, _DIGEST),
        coverage=_coverage(_SCOPE_REDUCED),
        provenance=_provenance(),
    )


def _case() -> DeterministicCase:
    """A claim, a finding about it, the repair (action, evidence, result) and an answer citing it.

    Unrelated frontier references make the review packet's reference scope reduced.
    """

    return make_case(
        plans={1: plan_record(PlanPublishedPayload(1, "Ship the parser", (obl(1),)), 1)},
        obligations={
            obl(1): obligation_record(
                ObligationPublishedPayload(
                    obl(1), "Parse offsets", "tests pass", ObligationStatus.OPEN
                ),
                2,
            )
        },
        claims={
            clm(1): record(
                ClaimRecordedPayload(
                    clm(1),
                    ClaimKind.COMPLETION,
                    "Offsets are validated",
                    (obl(1),),
                    obligation_refs=(obl(1),),
                ),
                3,
            )
        },
        findings={fnd(1): record(_finding(), 4)},
        actions={act(9): record(ActionRecordedPayload(act(9), ActionKind.EDIT, "Repair"), 5)},
        evidence={
            _REPAIR: evidence_record(
                EvidenceRecordedPayload(
                    _REPAIR,
                    EvidenceKind.TEST_RESULT,
                    EvidenceImmutability.METADATA_ONLY,
                    timestamp_from_string("2026-07-01T00:00:00.000Z"),
                    description="test output: 12 passed, offsets rejected when negative",
                ),
                6,
            )
        },
        results={
            res(7): record(
                ResultRecordedPayload(
                    res(7), act(9), ResultOutcome.SUCCESS, 0, evidence_refs=(_REPAIR,)
                ),
                7,
            )
        },
        responses={
            fnd(1): record(
                ResponseRecordedPayload(
                    finding_id=fnd(1),
                    finding_frontier=Frontier(4, _DIGEST),
                    disposition=ResponseDisposition.ACKNOWLEDGED,
                    reason="Validated offsets and recorded the test run.",
                    evidence_refs=(_REPAIR,),
                ),
                8,
            )
        },
        extra_refs=tuple(evt(900 + number) for number in range(8)),
    )


def _semantic(selection: ReviewSelectionPolicy, profile: ReviewContextProfile) -> SemanticCase:
    return build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000904",
        frozen_case=_case(),
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=profile,
        review_selection=selection,
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
    )


def _expanded() -> SemanticCase:
    profile = ReviewContextProfile.EXPANDED
    return _semantic(ReviewSelectionPolicy.for_profile(profile), profile)


def _offered(case: SemanticCase) -> set[str]:
    candidate = semantic_case_to_candidate_context(
        case,
        request_id="req_10000000-0000-4000-8000-000000000904",
        scope=_SCOPE,
        provider_binding=_BINDING,
    )
    return {item.item_id for item in candidate.items}


def _sent_refs(case: SemanticCase, approved: set[str]) -> frozenset[str]:
    refs = review_packet_content_refs(semantic_case_to_prepared_payload(case, approved))
    assert refs is not None
    return refs


def _blockers(
    included: frozenset[str],
    case: DeterministicCase | None = None,
    finding: Finding | None = None,
) -> tuple[str, ...]:
    """What a completed reduced review that sent exactly *included* proves about ``fnd(1)``."""

    case = _case() if case is None else case
    check = CheckRecordedPayload(
        mode=CheckMode.SEMANTIC_REQUIRED,
        policies=(PolicyVersion("work-integrity", "0.1.0"),),
        scope=CheckScopeModel(claim_ids=(), obligation_ids=()),
        policy_executions=(
            CheckPolicyExecutionModel(
                policy_id="work-integrity",
                policy_version="0.1.0",
                outcome="run",
                reason="completed",
            ),
        ),
        subject_frontier=case.frontier,
        verdict=CheckVerdict.NO_ISSUE_DETECTED,
        returned_finding_ids=(),
        suppressed_count=0,
        coverage=_coverage(_SCOPE_REDUCED),
        semantic_status=SemanticStatus.SUCCEEDED,
        semantic_reason=SemanticReason.SEMANTIC_COMPLETED,
        engine_version="0.1.0",
        projection_version="yoetz/0.1.0",
        semantic_provenance=_provenance(),
        semantic_conclusion="no_material_discrepancy",
        semantic_included_refs=tuple(sorted(included, key=str.encode)) or None,
    )
    return resolution_blockers(
        _finding() if finding is None else finding,
        4,
        check,
        frozenset(),
        proof_state=case.projection,
    )


def test_a_repair_the_packet_actually_sent_resolves_the_finding() -> None:
    semantic = _expanded()
    assert semantic.omitted_reference_count > 0, "the scope must be reduced"
    sent = _sent_refs(semantic, _offered(semantic))
    assert {_REPAIR, str(clm(1))} <= sent
    assert _blockers(sent) == ()


def test_a_repair_omitted_as_not_selected_leaves_the_finding_open() -> None:
    """The evidence excerpt was not selected: its ref appears only in an omission row.

    The builder's reference closure still names it (that is what the first fix recorded), but the
    reviewer never saw its content, so the scope keeps blocking.
    """

    profile = ReviewContextProfile.CUSTOM
    selection = ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED)
    selection = ReviewSelectionPolicy(
        sections=selection.sections,
        excerpt_kinds=(),
        relevance=selection.relevance,
        include_finding_prose=selection.include_finding_prose,
        include_exact_command_text=selection.include_exact_command_text,
        max_timeline_items=selection.max_timeline_items,
        max_assessments=selection.max_assessments,
        max_change_observations=selection.max_change_observations,
        max_excerpts=selection.max_excerpts,
        max_omissions=selection.max_omissions,
        max_excerpt_bytes=selection.max_excerpt_bytes,
        max_total_excerpt_bytes=selection.max_total_excerpt_bytes,
    )
    semantic = _semantic(selection, profile)
    assert semantic.omitted_reference_count > 0
    omitted = {
        (row.subject_ref, row.reason)
        for row in semantic.packet.omissions
        if row.subject_ref == _REPAIR
    }
    assert omitted and all(reason == "not_selected" for _ref, reason in omitted)
    assert _REPAIR in semantic.frontier_refs, "mentioned by the omission row and by the result"

    sent = _sent_refs(semantic, _offered(semantic))
    assert _REPAIR not in sent
    assert _blockers(sent) == _OUTSIDE
    # What 7c2988f5 recorded, the pre-minimization reference closure, would have resolved it.
    assert _blockers(semantic.frontier_refs) == ()


def test_a_per_item_privacy_drop_of_the_repair_leaves_the_finding_open() -> None:
    """Privacy minimization withheld the repair excerpt (a per-item data-class decision)."""

    semantic = _expanded()
    offered = _offered(semantic)
    excerpts = {
        item.item_id
        for item in semantic.items
        if item.section == "excerpt" and item.source_ref == _REPAIR
    }
    assert excerpts and excerpts <= offered
    approved = offered - excerpts
    assert REVIEW_PACKET_ITEM_ID in approved

    sent = _sent_refs(semantic, approved)
    assert _REPAIR not in sent
    assert _blockers(sent) == _OUTSIDE
    assert _REPAIR in semantic.frontier_refs
    assert _blockers(semantic.frontier_refs) == ()


def test_only_a_readable_review_packet_yields_sent_references() -> None:
    assert review_packet_content_refs(b"not json") is None
    assert review_packet_content_refs(b'{"schema":"other"}') is None
    semantic = _expanded()
    document = semantic_case_to_prepared_payload(semantic, _offered(semantic))
    sent = review_packet_content_refs(document)
    assert sent is not None and sent <= semantic.frontier_refs


def test_a_carried_multi_part_excerpt_carries_every_part_it_combines() -> None:
    """A captured multi-part group is one excerpt keyed by its lead evidence (issue #904).

    Its other parts are its ``evd_`` linked references and count as sent with it; a linked claim
    or event does not, and nothing counts when the lead excerpt itself was left out.
    """

    from finishup.application.semantic_case import review_packet_disclosure
    from finishup.protocol.canonical import JsonValue, canonical_encode

    lead, part, claim, event = str(evd(1)), str(evd(2)), str(clm(1)), str(evt(3))

    def carried(*omitted: str) -> frozenset[str]:
        document = {
            "schema": "yoetz.review-packet-case/2",
            "frontier_refs": sorted([lead, part, claim, event]),
            "items": [
                {
                    "item_id": "excerpt-lead",
                    "section": "excerpt",
                    "category": "evidence_excerpt",
                    "source_ref": lead,
                    "linked_subject_refs": sorted([lead, part, claim, event]),
                }
            ],
            "review_packet": {
                "omissions": [
                    {"subject_ref": ref, "category": "evidence_excerpt", "reason": "not_selected"}
                    for ref in omitted
                ]
            },
        }
        read = review_packet_disclosure(canonical_encode(cast(JsonValue, document)))
        assert read is not None
        return read.carried

    assert carried() == frozenset({lead, part})
    assert carried(lead) == frozenset()


def _history_case(evidence: EvidenceRecordedPayload) -> DeterministicCase:
    """``_case`` with *evidence* as the repair, frozen the way production freezes it.

    Recorded history is available, so results and evidence travel as the history items of the
    events that recorded them, keyed by those ``evt_`` ids.
    """

    from finishup.domain.events import EVIDENCE_SCHEMA_VERSION, encode_payload
    from finishup.kernel.deterministic_checks import FrozenHistoryEvent

    base = _case()
    projection = base.projection
    case = make_case(
        plans=projection.plans,
        obligations=projection.obligations,
        claims=projection.claims,
        findings=projection.findings,
        actions=projection.actions,
        evidence={_REPAIR: evidence_record(evidence, 6)},
        results=projection.results,
        responses=projection.responses,
        extra_refs=tuple(evt(900 + number) for number in range(8)),
    )
    rows = sorted(
        (("action_recorded", "1.0.0", row) for row in case.projection.actions.values()),
        key=lambda item: item[2].source_frontier,
    )
    rows += [("evidence_recorded", EVIDENCE_SCHEMA_VERSION, case.projection.evidence[_REPAIR])]
    rows += [("result_recorded", "1.0.0", row) for row in case.projection.results.values()]
    history = tuple(
        FrozenHistoryEvent(
            event_id=row.source_event_id,
            schema_name=name,
            schema_version=version,
            ingestion_sequence=row.source_frontier,
            occurred_at="2026-07-01T00:00:00.000Z",
            accepted_at=None,
            occurred_at_consistency=None,
            payload_digest=row.payload_digest,
            content_visibility="available",
            payload=encode_payload(row.payload),  # type: ignore[arg-type]
        )
        for name, version, row in sorted(rows, key=lambda item: item[2].source_frontier)
    )
    return replace(case, history=history, history_availability="available")


def _captured() -> EvidenceRecordedPayload:
    """Repair evidence whose content is an observation-captured object."""

    from finishup.domain.events import (
        EvidenceContentAvailability,
        EvidenceDigestBinding,
        EvidenceDigestProvenance,
        EvidenceDigestSubject,
    )
    from finishup.domain.values import object_id

    return EvidenceRecordedPayload(
        evidence_id=_REPAIR,
        evidence_kind=EvidenceKind.OTHER,
        strength=EvidenceImmutability.IMMUTABLE_SNAPSHOT,
        observed_at=timestamp_from_string("2026-07-01T00:00:00.000Z"),
        captured_object_id=object_id("obj_00000000-0000-4000-8000-000000000904"),
        content_digest="sha256:" + "4" * 64,
        description="Observation-captured test output bytes part=1/1",
        digest_binding=EvidenceDigestBinding(
            subject=EvidenceDigestSubject.BOUNDED_EXCERPT,
            content_availability=EvidenceContentAvailability.CAPTURED,
            byte_count=64,
            provenance=EvidenceDigestProvenance.OBSERVATION_CAPTURED,
        ),
    )


def _history_blockers(
    case: DeterministicCase, selection: ReviewSelectionPolicy
) -> tuple[SemanticCase, frozenset[str], frozenset[str], tuple[str, ...]]:
    """Build, send and read the packet for *case*, then ask what it proves about ``fnd(1)``.

    Returns the case, the history events that carried their payload, the sent ledger refs, and the
    resolution blockers.
    """

    from finishup.application.semantic_case import review_packet_disclosure, sent_ledger_refs

    semantic = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000905",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.CUSTOM,
        review_selection=selection,
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
    )
    disclosure = review_packet_disclosure(
        semantic_case_to_prepared_payload(semantic, _offered(semantic))
    )
    assert disclosure is not None
    sent = sent_ledger_refs(disclosure, case.projection)
    return semantic, disclosure.payload_events, sent, _blockers(sent, case)


def _selection(*, excerpts: bool, max_omissions: int) -> ReviewSelectionPolicy:
    base = ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED)
    return ReviewSelectionPolicy(
        sections=base.sections,
        excerpt_kinds=base.excerpt_kinds if excerpts else (),
        relevance=base.relevance,
        include_finding_prose=base.include_finding_prose,
        include_exact_command_text=base.include_exact_command_text,
        max_timeline_items=base.max_timeline_items,
        max_assessments=base.max_assessments,
        max_change_observations=base.max_change_observations,
        max_excerpts=base.max_excerpts,
        max_omissions=max_omissions,
        max_excerpt_bytes=base.max_excerpt_bytes,
        max_total_excerpt_bytes=base.max_total_excerpt_bytes,
    )


def test_captured_evidence_whose_bytes_were_never_resolved_is_not_credited() -> None:
    """A captured repair with no resolved bytes gets a ``not_recorded`` omission (#904, A).

    Its recording event travelled with its payload, but that payload only describes bytes the
    reviewer never saw, so the record is not credited and the finding stays open.
    """

    case = _history_case(_captured())
    assert case.history_availability == "available"
    semantic, payload_events, sent, blockers = _history_blockers(
        case, _selection(excerpts=True, max_omissions=64)
    )
    reasons = {row.reason for row in semantic.packet.omissions if row.subject_ref == _REPAIR}
    assert reasons == {"not_recorded"}
    assert str(evt(6)) in payload_events, "its recording event travelled with its payload"
    assert _REPAIR not in sent
    assert blockers == _OUTSIDE


def test_captured_evidence_left_out_stays_open_even_when_its_omission_row_is_capped() -> None:
    """With ``max_omissions=0`` no omission row says the excerpt was left out (#904, B).

    Credit never depends on an omission row surviving the cap: captured evidence needs its own
    carried excerpt.
    """

    case = _history_case(_captured())
    semantic, payload_events, sent, blockers = _history_blockers(
        case, _selection(excerpts=False, max_omissions=0)
    )
    assert semantic.packet.omissions == ()
    assert not any(item.source_ref == _REPAIR for item in semantic.items)
    assert str(evt(6)) in payload_events
    assert _REPAIR not in sent
    assert blockers == _OUTSIDE


def test_recorded_evidence_carried_by_its_event_is_credited_without_omission_rows() -> None:
    """Evidence whose payload is its content counts through its event whatever rows survive."""

    evidence = EvidenceRecordedPayload(
        _REPAIR,
        EvidenceKind.TEST_RESULT,
        EvidenceImmutability.METADATA_ONLY,
        timestamp_from_string("2026-07-01T00:00:00.000Z"),
        description="test output: 12 passed, offsets rejected when negative",
    )
    case = _history_case(evidence)
    _semantic, payload_events, sent, blockers = _history_blockers(
        case, _selection(excerpts=False, max_omissions=0)
    )
    assert str(evt(6)) in payload_events
    assert _REPAIR in sent
    assert blockers == ()


def test_a_history_item_replaced_by_the_size_marker_carries_no_payload() -> None:
    from finishup.application.semantic_case import review_packet_disclosure
    from finishup.protocol.canonical import JsonValue, canonical_encode

    event = str(evt(6))

    def payload_events(content: dict[str, JsonValue]) -> frozenset[str]:
        document: dict[str, JsonValue] = {
            "schema": "yoetz.review-packet-case/2",
            "frontier_refs": [event],
            "items": [
                {
                    "item_id": f"history-{event}",
                    "section": "timeline",
                    "category": "evidence_excerpt",
                    "source_ref": event,
                    "content": canonical_encode(cast(JsonValue, content)).decode("utf-8"),
                }
            ],
            "review_packet": {"omissions": []},
        }
        read = review_packet_disclosure(canonical_encode(cast(JsonValue, document)))
        assert read is not None
        return read.payload_events

    assert payload_events({"event_id": event, "payload": {"evidence_id": str(_REPAIR)}}) == {event}
    assert payload_events({"event_id": event, "kind": "evidence_recorded"}) == frozenset()
    assert (
        payload_events(
            {"reason": "over_case_item_limit", "schema": "yoetz.bounded-content-omission/1"}
        )
        == frozenset()
    )


# Issue #947: references a reviewer cites and references a packet carries are aliased both ways.


def test_the_finding_counts_as_sent_through_its_structural_prior_finding_row() -> None:
    """The row names the finding's subjects and the agent's answer; prose rows alone do not.

    A ``not_recorded`` omission on its prose (a finding recorded before challenge fields existed)
    leaves the row as all the ledger holds, so it still counts; a withholding omission does not.
    """

    from finishup.application.semantic_case import review_packet_disclosure
    from finishup.protocol.canonical import JsonValue, canonical_encode

    finding = str(fnd(1))

    def carried(item_ids: tuple[str, ...], reason: str | None = None) -> frozenset[str]:
        document: dict[str, JsonValue] = {
            "schema": "yoetz.review-packet-case/2",
            "frontier_refs": [finding],
            "items": [
                {"item_id": item_id, "section": "prior_finding", "source_ref": finding}
                for item_id in item_ids
            ],
            "review_packet": {
                "omissions": []
                if reason is None
                else [{"subject_ref": finding, "category": "finding_summary", "reason": reason}]
            },
        }
        read = review_packet_disclosure(canonical_encode(cast(JsonValue, document)))
        assert read is not None
        return read.carried

    row, prose = f"prior-finding-{finding}", f"prior-finding-summary-{finding}"
    assert carried((row, prose)) == {finding}
    assert carried((row,), "not_recorded") == {finding}
    assert carried((prose,)) == frozenset()
    assert carried((row, prose), "not_selected") == frozenset()

    # The real packet: the legacy finding's prose is ``not_recorded``, its row was carried.
    semantic = _expanded()
    sent = _sent_refs(semantic, _offered(semantic))
    assert finding in sent
    assert _blockers(sent - {finding}) == _OUTSIDE


def test_a_carried_excerpt_credits_the_event_that_recorded_it() -> None:
    """A reviewer cites evidence by its ``evt_``; the packet carried it as its ``evd_`` excerpt."""

    semantic = _expanded()
    sent = _sent_refs(semantic, _offered(semantic))
    recording = str(evt(6))
    assert _REPAIR in sent and recording not in sent
    cites_event = replace(_finding(), subject_refs=(recording,))  # type: ignore[arg-type]
    assert _blockers(sent, finding=cites_event) == ()
    # Without the excerpt nothing stands in for the event: it is neither sent nor evicted.
    excerpts = {
        item.item_id
        for item in semantic.items
        if item.section == "excerpt" and item.source_ref == _REPAIR
    }
    dropped = _sent_refs(semantic, _offered(semantic) - excerpts)
    assert _blockers(dropped, finding=cites_event) == _OUTSIDE


def test_a_history_row_with_its_payload_credits_its_action_and_claim_records() -> None:
    """The reverse direction is recorded at check time, for every record family a row carries.

    The superseded claim the reviewer criticised travels only as its history row (claims are
    carried as items only while effective), so the row is what shows it to the reviewer.
    """

    from builders.policy_cases import claim_record
    from finishup.application.semantic_case import review_packet_disclosure, sent_ledger_refs
    from finishup.domain.events import (
        ClaimRecordedPayloadV1_1,
        encode_payload,
    )
    from finishup.kernel.deterministic_checks import FrozenHistoryEvent

    base = _history_case(
        EvidenceRecordedPayload(
            _REPAIR,
            EvidenceKind.TEST_RESULT,
            EvidenceImmutability.METADATA_ONLY,
            timestamp_from_string("2026-07-01T00:00:00.000Z"),
            description="test output: 12 passed, offsets rejected when negative",
        )
    )
    projection = base.projection
    original = projection.claims[clm(1)]
    corrected = claim_record(
        ClaimRecordedPayloadV1_1(
            clm(2),
            ClaimKind.COMPLETION,
            "Offsets are validated and tested",
            (_REPAIR,),
            obligation_refs=(obl(1),),
            supersedes_claim_refs=(clm(1),),
        ),
        9,
    )
    claims = {clm(1): replace(original, superseded_by_claim_id=clm(2)), clm(2): corrected}
    case = make_case(
        plans=projection.plans,
        obligations=projection.obligations,
        claims=claims,
        findings=projection.findings,
        actions=projection.actions,
        evidence=projection.evidence,
        results=projection.results,
        responses=projection.responses,
        extra_refs=tuple(evt(900 + number) for number in range(8)),
    )
    claim_rows = tuple(
        FrozenHistoryEvent(
            event_id=row.source_event_id,
            schema_name="claim_recorded",
            schema_version="1.1.0" if key == clm(2) else "1.0.0",
            ingestion_sequence=row.source_frontier,
            occurred_at="2026-07-01T00:00:00.000Z",
            accepted_at=None,
            occurred_at_consistency=None,
            payload_digest=row.payload_digest,
            content_visibility="available",
            payload=encode_payload(row.payload),  # type: ignore[arg-type]
        )
        for key, row in claims.items()
    )
    history = tuple(sorted((*base.history, *claim_rows), key=lambda item: item.ingestion_sequence))
    case = replace(case, history=history, history_availability="available")

    semantic = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000947",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.CUSTOM,
        # No excerpts and no omission rows: every record reaches the reviewer as its history row.
        review_selection=_selection(excerpts=False, max_omissions=0),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
    )
    disclosure = review_packet_disclosure(
        semantic_case_to_prepared_payload(semantic, _offered(semantic))
    )
    assert disclosure is not None
    sent = sent_ledger_refs(disclosure, case.projection)
    assert str(evt(3)) in disclosure.payload_events and str(evt(5)) in disclosure.payload_events
    assert str(clm(1)) not in disclosure.carried and str(clm(1)) in sent
    assert str(act(9)) not in disclosure.carried and str(act(9)) in sent
    assert _blockers(sent, case) == ()
