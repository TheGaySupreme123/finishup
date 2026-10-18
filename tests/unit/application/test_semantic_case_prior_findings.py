"""The prior-findings section carries the review dialogue into the next review (issue #905).

The reviewer has no memory between checks. Before this section, earlier findings and the main
agent's answers reached it only as raw timeline rows inside the last 64 events, which hook rows
pushed out, and the stored finding had lost what the reviewer asked for. These tests pin the
bounded, ledger-backed section that replaces that accident.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from types import MappingProxyType
from typing import cast

import pytest

from builders.dialogue import limit_decision
from builders.policy_cases import (
    BASE_COVERAGE,
    FRONTIER,
    act,
    clm,
    evd,
    evidence_record,
    evt,
    finding_record,
    fnd,
    make_case,
    obl,
    obligation_record,
    record,
    res,
)
from finishup.application import semantic_case as semantic_case_module
from finishup.application.missing_for_assessment import ReviewFollowUp, ReviewFollowUpItem
from finishup.application.semantic_case import (
    AGENT_DISCLOSURES_ITEM_ID,
    MAX_PRIOR_FINDINGS,
    build_semantic_case,
    semantic_case_to_prepared_payload,
)
from finishup.domain.events import (
    EvidenceKind,
    EvidenceRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    ResponseDisposition,
    ResponseRecordedPayload,
    ResultOutcome,
    ResultRecordedPayload,
)
from finishup.domain.findings import (
    Finding,
    FindingChallenge,
    FindingKind,
    FindingOrigin,
    SamplingParams,
    SemanticDispatchKind,
    SemanticProvenance,
)
from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from finishup.domain.receipts import SEMANTIC_PRIOR_FINDINGS_OVER_LIMIT_GAP
from finishup.domain.values import EventId, FindingId, ObligationId, timestamp_from_string
from finishup.kernel.deterministic_checks import DeterministicCase
from finishup.kernel.projections import (
    DecisionProjectionRecord,
    FindingProjectionRecord,
    ObligationProjectionRecord,
    ProjectionRecord,
)
from finishup.ports.semantic import SemanticCase
from finishup.protocol.canonical import JsonValue, strict_json_parse
from finishup.protocol.coverage import EvidenceImmutability
from finishup.protocol.models import DataCategory, SemanticReason, SemanticStatus

_DIGEST = "sha256:" + "1" * 64
_NOW = timestamp_from_string("2026-09-28T12:00:00.000Z")


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


def _semantic(
    number: int,
    *,
    challenge: FindingChallenge | None = None,
    related: tuple[FindingId, ...] = (),
    origin: FindingOrigin = FindingOrigin.SEMANTIC_MODEL_DERIVED,
) -> Finding:
    return Finding(
        finding_id=fnd(number),
        kind=FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
        origin=origin,
        priority=1,
        summary=f"Required llvmlite 0.46.0 verification remains open ({number}).",
        detail="Make one concrete authorized attempt to obtain llvmlite 0.46.0.",
        subject_refs=(obl(1),),
        policy_id="work-integrity",
        policy_version="0.1.0",
        subject_frontier=FRONTIER,
        coverage=BASE_COVERAGE,
        provenance=None if origin is FindingOrigin.DETERMINISTIC else _provenance(),
        challenge=challenge,
        related_finding_ids=related,
    )


_CHALLENGE = FindingChallenge(
    discrepancy="The claim is complete while the llvmlite 0.46.0 obligation is open.",
    alternative_interpretation="The package index may be unreachable from this sandbox.",
    requested_next_step="act",
    uncertainty="The recorded install failure may already be the authorized attempt.",
)


def _numba_case(
    extra_findings: Mapping[FindingId, FindingProjectionRecord] | None = None,
    extra_responses: Mapping[FindingId, ProjectionRecord[ResponseRecordedPayload]] | None = None,
) -> DeterministicCase:
    """numba-stencil-boundary-modes: a legacy finding, a restatement, two blocked attempts."""

    obligation = obligation_record(
        ObligationPublishedPayload(
            obl(1), "Verify with llvmlite 0.46.0", "stencil tests pass", ObligationStatus.OPEN
        ),
        2,
    )
    attempts = {
        res(number): record(
            ResultRecordedPayload(
                result_id=res(number),
                action_id=act(number),
                outcome=ResultOutcome.FAILURE,
                summary=f"Package index reported no matching llvmlite==0.46.0 ({number}).",
            ),
            sequence,
        )
        for number, sequence in ((1, 12), (2, 14))
    }
    stale = evidence_record(
        EvidenceRecordedPayload(
            evd(1),
            EvidenceKind.COMMAND_OUTPUT,
            EvidenceImmutability.METADATA_ONLY,
            _NOW,
            description="pip install llvmlite==0.46.0: connection reset",
        ),
        3,
    )
    response = ResponseRecordedPayload(
        finding_id=fnd(2),
        finding_frontier=FRONTIER,
        disposition=ResponseDisposition.REJECTED,
        reason=(
            "The instruction to make an attempt has already been met: two exact-version "
            "installation attempts failed because the package index was unavailable."
        ),
        evidence_refs=(res(1), res(2)),
    )
    findings: dict[FindingId, FindingProjectionRecord] = {
        fnd(1): finding_record(_semantic(1), 5),
        fnd(2): finding_record(_semantic(2, challenge=_CHALLENGE, related=(fnd(1),)), 10),
    }
    if extra_findings is not None:
        findings.update(extra_findings)
    return make_case(
        obligations={obl(1): obligation},
        results=attempts,
        evidence={evd(1): stale},
        findings=findings,
        responses={fnd(2): record(response, 16), **(extra_responses or {})},
        extra_refs=(obl(1), clm(1)),
    )


def _build(
    case: DeterministicCase,
    profile: ReviewContextProfile = ReviewContextProfile.GOAL_AWARE,
    *,
    selection: ReviewSelectionPolicy | None = None,
    follow_up: ReviewFollowUp | None = None,
) -> SemanticCase:
    return build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=profile,
        review_selection=selection or ReviewSelectionPolicy.for_profile(profile),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        follow_up=follow_up,
    )


def _row(case: SemanticCase, item_id: str) -> Mapping[str, JsonValue]:
    item = next(item for item in case.items if item.item_id == item_id)
    return cast(Mapping[str, JsonValue], strict_json_parse(item.content))


def test_prior_findings_carry_the_challenge_the_answer_and_newer_material() -> None:
    case = _build(_numba_case())

    first, second = f"prior-finding-{fnd(1)}", f"prior-finding-{fnd(2)}"
    assert first in case.packet.prior_finding_item_ids
    assert second in case.packet.prior_finding_item_ids
    restated = _row(case, second)
    assert restated["finding_ref"] == str(fnd(2))
    assert restated["challenge_fields"] == "recorded"
    assert restated["requested_next_step"] == "act"
    assert restated["relates_to"] == [str(fnd(1))]
    response = cast(Mapping[str, JsonValue], restated["response"])
    assert response["disposition"] == "rejected"
    assert response["evidence_refs"] == [str(res(1)), str(res(2))]
    # The two blocked attempts were recorded after the finding; the older evidence was not.
    assert restated["recorded_after_finding"] == [str(res(2)), str(res(1))]
    texts = {
        item.item_id: item.content.decode("utf-8")
        for item in case.items
        if item.section == "prior_finding" and item.category is DataCategory.FINDING_SUMMARY
    }
    assert _CHALLENGE.discrepancy in texts[f"prior-finding-discrepancy-{fnd(2)}"]
    assert _CHALLENGE.uncertainty in texts[f"prior-finding-uncertainty-{fnd(2)}"]
    assert "already been met" in texts[f"prior-finding-response-{fnd(2)}"]
    # Everything the reviewer would cite for a verdict is citable.
    assert {str(fnd(1)), str(fnd(2)), str(res(1)), str(res(2))} <= case.frontier_refs
    payload = cast(
        Mapping[str, JsonValue],
        strict_json_parse(
            semantic_case_to_prepared_payload(case, {item.item_id for item in case.items})
        ),
    )
    packet = cast(Mapping[str, JsonValue], payload["review_packet"])
    assert packet["prior_finding_item_ids"] == list(case.packet.prior_finding_item_ids)


def test_a_follow_up_packet_still_carries_the_supported_rebuttal() -> None:
    """Issue #1079: rebuilding the case for a follow-up keeps the answer that cites evidence."""

    follow_up = ReviewFollowUp(
        round=1,
        items=(
            ReviewFollowUpItem(
                kind="verification_output",
                target_refs=(str(res(1)),),
                source_refs=frozenset({str(res(1)), str(res(2)), str(evd(1))}),
            ),
        ),
        shown_refs=frozenset(),
    )
    built = _build(_numba_case(), follow_up=follow_up)
    texts = {
        item.item_id: item.content.decode("utf-8")
        for item in built.items
        if item.section == "prior_finding" and item.category is DataCategory.FINDING_SUMMARY
    }
    assert "already been met" in texts[f"prior-finding-response-{fnd(2)}"]
    response = cast(Mapping[str, JsonValue], _row(built, f"prior-finding-{fnd(2)}")["response"])
    assert response["disposition"] == "rejected"
    assert response["evidence_refs"] == [str(res(1)), str(res(2))]


def test_three_prose_bearing_findings_give_one_rulable_ref_each() -> None:
    """The reviewer rules once per finding, however many prose rows each one carries (#905).

    With finding prose selected, each earlier finding contributes its structural row plus up to
    six prose rows. The rulable list names each carried finding once, newest first, so a
    provider answering it cannot spend the eight-ruling cap on one finding's rows.
    """

    answer = ResponseRecordedPayload(
        finding_id=fnd(3),
        finding_frontier=FRONTIER,
        disposition=ResponseDisposition.REJECTED,
        reason="The sandbox has no route to the package index; the attempt is recorded.",
        evidence_refs=(res(2),),
    )
    third = finding_record(_semantic(3, challenge=_CHALLENGE, related=(fnd(2),)), 18)
    case = _build(_numba_case({fnd(3): third}, {fnd(3): record(answer, 19)}))

    refs = (str(fnd(3)), str(fnd(2)), str(fnd(1)))
    assert case.packet.prior_finding_refs == refs
    assert len(case.packet.prior_finding_item_ids) > len(refs)
    for ref in refs:
        assert f"prior-finding-{ref}" in case.packet.prior_finding_item_ids
        rows = [item for item in case.items if item.section == "prior_finding"]
        assert sum(1 for item in rows if item.source_ref == ref) > 1
    payload = cast(
        Mapping[str, JsonValue],
        strict_json_parse(
            semantic_case_to_prepared_payload(case, {item.item_id for item in case.items})
        ),
    )
    packet = cast(Mapping[str, JsonValue], payload["review_packet"])
    assert packet["prior_finding_refs"] == list(refs)


def test_a_legacy_finding_degrades_to_summary_and_message_with_an_explicit_omission() -> None:
    case = _build(_numba_case())

    legacy = _row(case, f"prior-finding-{fnd(1)}")
    assert legacy["challenge_fields"] == "not_recorded"
    assert "requested_next_step" not in legacy
    assert set(cast(Mapping[str, JsonValue], legacy["text_item_ids"])) == {"message", "summary"}
    assert any(
        omission.subject_ref == str(fnd(1))
        and omission.category is DataCategory.FINDING_SUMMARY
        and omission.reason == "not_recorded"
        for omission in case.packet.omissions
    )


def test_the_structural_profile_carries_only_the_structural_rows() -> None:
    case = _build(_numba_case(), ReviewContextProfile.STRUCTURAL)

    rows = [item for item in case.items if item.section == "prior_finding"]
    assert {item.item_id for item in rows} == {
        f"prior-finding-{fnd(1)}",
        f"prior-finding-{fnd(2)}",
    }
    assert all(item.category is DataCategory.BOUNDED_STRUCTURAL_METADATA for item in rows)
    assert "text_item_ids" not in _row(case, f"prior-finding-{fnd(2)}")


def test_local_and_resolved_findings_are_not_live_questions_for_the_reviewer() -> None:
    resolved = finding_record(
        _semantic(3, challenge=_CHALLENGE), 6, resolved_by_check_event_id=evt(90)
    )
    local = finding_record(_semantic(4, origin=FindingOrigin.DETERMINISTIC), 7)
    case = _build(_numba_case({fnd(3): resolved, fnd(4): local}))

    carried = {item.source_ref for item in case.items if item.section == "prior_finding"}
    assert carried == {str(fnd(1)), str(fnd(2))}


def test_the_section_is_bounded_and_says_so_when_it_truncates() -> None:
    extra = {
        fnd(number): finding_record(_semantic(number, challenge=_CHALLENGE), 20 + number)
        for number in range(3, 3 + MAX_PRIOR_FINDINGS)
    }
    case = _build(_numba_case(extra))

    carried = {item.source_ref for item in case.items if item.section == "prior_finding"}
    assert len(carried) == MAX_PRIOR_FINDINGS
    # Newest first: the two oldest rows of the dialogue are the ones not carried.
    assert str(fnd(1)) not in carried
    assert str(fnd(2)) not in carried
    assert SEMANTIC_PRIOR_FINDINGS_OVER_LIMIT_GAP in case.packet.coverage.known_gaps
    omitted = {
        omission.subject_ref
        for omission in case.packet.omissions
        if omission.reason == "not_selected" and omission.source_kind == "finding"
    }
    assert {str(fnd(1)), str(fnd(2))} <= omitted


def test_the_section_is_not_crowded_out_by_the_timeline_budget() -> None:
    selection = replace(
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.GOAL_AWARE), max_timeline_items=0
    )
    case = _build(_numba_case(), ReviewContextProfile.CUSTOM, selection=selection)

    assert case.packet.timeline_item_ids == ()
    assert f"prior-finding-{fnd(2)}" in case.packet.prior_finding_item_ids


def test_a_case_without_prior_findings_is_unchanged_apart_from_the_empty_list() -> None:
    case = _build(make_case(extra_refs=(clm(1),)))

    assert case.packet.prior_finding_item_ids == ()
    assert not any(item.section == "prior_finding" for item in case.items)


def test_envelope_pressure_removes_the_oldest_prior_findings_before_any_work_content() -> None:
    """The dialogue section yields first, so it never displaces an excerpt (review of #905)."""

    from finishup.application.semantic_case import (
        _drop_prior_finding_rows,  # pyright: ignore[reportPrivateUsage]
    )
    from finishup.domain.privacy import MAX_EGRESS_ENVELOPE_BYTES
    from finishup.protocol.canonical import canonical_encode

    def row(item_id: str, section: str, source: str) -> dict[str, JsonValue]:
        return {"item_id": item_id, "section": section, "source_ref": source}

    older, newer = str(fnd(1)), str(fnd(2))
    rows: list[JsonValue] = [
        row(f"prior-finding-{older}", "prior_finding", older),
        row(f"prior-finding-summary-{older}", "prior_finding", older),
        row(f"prior-finding-{newer}", "prior_finding", newer),
        row("excerpt-evd", "excerpt", str(evd(1))),
    ]
    envelope: dict[str, JsonValue] = {
        "item_catalog": rows,
        "review_packet": {
            "coverage": {"known_gaps": []},
            "prior_finding_item_ids": [
                f"prior-finding-{older}",
                f"prior-finding-summary-{older}",
                f"prior-finding-{newer}",
            ],
            "prior_finding_refs": [newer, older],
        },
        "filler": "",
    }
    base = len(canonical_encode(cast(JsonValue, envelope)))
    envelope["filler"] = "x" * (MAX_EGRESS_ENVELOPE_BYTES - base + 40)

    assert _drop_prior_finding_rows(envelope) == 2
    kept = [
        cast(Mapping[str, JsonValue], item)["item_id"]
        for item in cast(list[JsonValue], envelope["item_catalog"])
    ]
    assert kept == [f"prior-finding-{newer}", "excerpt-evd"]
    packet = cast(Mapping[str, JsonValue], envelope["review_packet"])
    assert packet["prior_finding_item_ids"] == [f"prior-finding-{newer}"]
    assert packet["prior_finding_refs"] == [newer]
    coverage = cast(Mapping[str, JsonValue], packet["coverage"])
    assert coverage["known_gaps"] == [SEMANTIC_PRIOR_FINDINGS_OVER_LIMIT_GAP]
    assert len(canonical_encode(cast(JsonValue, envelope))) <= MAX_EGRESS_ENVELOPE_BYTES


def test_settled_rows_leave_before_any_open_finding_and_never_set_the_gap() -> None:
    """Round-3 review: settled rows carry newer times, so oldest-first dropped open ones first."""

    from finishup.application.semantic_case import (
        _drop_prior_finding_rows,  # pyright: ignore[reportPrivateUsage]
    )
    from finishup.domain.privacy import MAX_EGRESS_ENVELOPE_BYTES
    from finishup.protocol.canonical import canonical_encode

    def row(item_id: str, source: str) -> dict[str, JsonValue]:
        return {"item_id": item_id, "section": "prior_finding", "source_ref": source}

    open_ref, settled_ref = str(fnd(1)), str(fnd(2))
    envelope: dict[str, JsonValue] = {
        "item_catalog": [
            row(f"prior-finding-{open_ref}", open_ref),
            row(f"settled-finding-{settled_ref}", settled_ref),
            row(f"settled-finding-summary-{settled_ref}", settled_ref),
        ],
        "review_packet": {
            "coverage": {"known_gaps": []},
            "prior_finding_item_ids": [f"prior-finding-{open_ref}"],
            "prior_finding_refs": [open_ref],
        },
        "filler": "",
    }
    base = len(canonical_encode(cast(JsonValue, envelope)))
    envelope["filler"] = "x" * (MAX_EGRESS_ENVELOPE_BYTES - base + 40)

    assert _drop_prior_finding_rows(envelope) == 2
    kept = [
        cast(Mapping[str, JsonValue], item)["item_id"]
        for item in cast(list[JsonValue], envelope["item_catalog"])
    ]
    assert kept == [f"prior-finding-{open_ref}"]
    packet = cast(Mapping[str, JsonValue], envelope["review_packet"])
    assert packet["prior_finding_refs"] == [open_ref]
    assert cast(Mapping[str, JsonValue], packet["coverage"])["known_gaps"] == []


def test_the_oldest_settled_finding_leaves_first() -> None:
    """Final review: catalog rows are oldest first, so the newest settlement stays nameable."""

    from finishup.application.semantic_case import (
        _drop_prior_finding_rows,  # pyright: ignore[reportPrivateUsage]
    )
    from finishup.domain.privacy import MAX_EGRESS_ENVELOPE_BYTES
    from finishup.protocol.canonical import canonical_encode

    older, newer = str(fnd(1)), str(fnd(2))
    envelope: dict[str, JsonValue] = {
        "item_catalog": [
            {
                "item_id": f"settled-finding-{older}",
                "section": "prior_finding",
                "source_ref": older,
            },
            {
                "item_id": f"settled-finding-{newer}",
                "section": "prior_finding",
                "source_ref": newer,
            },
        ],
        "review_packet": {
            "coverage": {"known_gaps": []},
            "prior_finding_item_ids": [],
            "prior_finding_refs": [],
        },
        "filler": "",
    }
    base = len(canonical_encode(cast(JsonValue, envelope)))
    envelope["filler"] = "x" * (MAX_EGRESS_ENVELOPE_BYTES - base + 20)

    assert _drop_prior_finding_rows(envelope) == 1
    kept = [
        cast(Mapping[str, JsonValue], item)["item_id"]
        for item in cast(list[JsonValue], envelope["item_catalog"])
    ]
    assert kept == [f"settled-finding-{newer}"]


_REDUCTION_KEYS = (
    "assessment_links_stripped_count",
    "catalog_dropped_count",
    "change_observations_dropped_count",
    "deterministic_assessments_dropped_count",
    "omissions_dropped_count",
    "targeted_excerpts_dropped_count",
)


def test_bounded_case_envelope_drops_prior_findings_first_and_accounts_for_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The bounding entry point, not only the helper, yields the dialogue section first."""

    from finishup.application import semantic_case as module
    from finishup.domain.privacy import MAX_EGRESS_ENVELOPE_BYTES
    from finishup.protocol.canonical import canonical_encode

    older, newer = str(fnd(1)), str(fnd(2))

    def row(item_id: str, section: str, source: str) -> dict[str, JsonValue]:
        return {"item_id": item_id, "section": section, "source_ref": source}

    def oversized(_case: object) -> dict[str, JsonValue]:
        envelope: dict[str, JsonValue] = {
            "item_catalog": [
                row(f"prior-finding-{older}", "prior_finding", older),
                row(f"prior-finding-{newer}", "prior_finding", newer),
                row("excerpt-evd", "excerpt", str(evd(1))),
            ],
            "review_packet": {
                "coverage": {"known_gaps": []},
                "prior_finding_item_ids": [f"prior-finding-{older}", f"prior-finding-{newer}"],
                "prior_finding_refs": [newer, older],
            },
            "filler": "",
        }
        probe = dict(envelope)
        module._set_selection_accounting(  # pyright: ignore[reportPrivateUsage]
            probe, dict.fromkeys(_REDUCTION_KEYS, 0)
        )
        # Over the limit by a few bytes: one prior-finding row must go, the excerpt must stay.
        envelope["filler"] = "x" * (
            MAX_EGRESS_ENVELOPE_BYTES - len(canonical_encode(cast(JsonValue, probe))) + 20
        )
        return envelope

    monkeypatch.setattr(module, "_case_envelope_json", oversized)
    bounded = cast(
        Mapping[str, JsonValue],
        strict_json_parse(module.bounded_case_envelope(_build(_numba_case()))),
    )
    kept = [
        cast(Mapping[str, JsonValue], item)["item_id"]
        for item in cast(list[JsonValue], bounded["item_catalog"])
    ]
    assert kept == [f"prior-finding-{newer}", "excerpt-evd"]
    packet_view = cast(Mapping[str, JsonValue], bounded["review_packet"])
    assert packet_view["prior_finding_refs"] == [newer]
    accounting = cast(Mapping[str, JsonValue], bounded["selection_accounting"])
    assert accounting["catalog_dropped_count"] == "1"
    packet = cast(Mapping[str, JsonValue], bounded["review_packet"])
    coverage = cast(Mapping[str, JsonValue], packet["coverage"])
    assert SEMANTIC_PRIOR_FINDINGS_OVER_LIMIT_GAP in cast(list[JsonValue], coverage["known_gaps"])


def test_the_packet_view_reports_prior_rows_bounding_removed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finishup.application import semantic_case as module
    from finishup.protocol.canonical import canonical_encode

    case = _build(_numba_case())
    assert any(item.section == "prior_finding" for item in case.items)
    assert module.semantic_case_packet_view(case).prior_findings_trimmed is False

    def emptied(_case: SemanticCase) -> bytes:
        return canonical_encode({"item_catalog": []})

    monkeypatch.setattr(module, "bounded_case_envelope", emptied)
    view = module.semantic_case_packet_view(case)
    assert view.prior_findings_trimmed is True
    assert view.prior_finding_refs == frozenset()


def test_a_selection_without_the_assessments_section_discloses_unshown_prior_findings() -> None:
    """With no section at all the reviewer sees no earlier finding: that is disclosed, so the
    kernel treats every unruled open AI-powered finding as not assessed (Greptile P1, #905)."""

    policy = ReviewSelectionPolicy.for_profile(ReviewContextProfile.GOAL_AWARE)
    without = replace(
        policy,
        sections=tuple(item for item in policy.sections if item != "deterministic_assessments"),
    )
    case = _build(_numba_case(), selection=without)
    assert not any(item.section == "prior_finding" for item in case.items)
    assert SEMANTIC_PRIOR_FINDINGS_OVER_LIMIT_GAP in case.packet.coverage.known_gaps
    shown = _build(_numba_case())
    assert any(item.section == "prior_finding" for item in shown.items)
    assert SEMANTIC_PRIOR_FINDINGS_OVER_LIMIT_GAP not in shown.packet.coverage.known_gaps


def test_answered_local_finding_reaches_the_reviewer_as_non_rulable_context() -> None:
    """TB4 tb4f1 atrx (issue #976): the agent's answer to FinishUP's own finding reaches the review.

    The deliverable finding was local, so its answer ("cannot honestly be populated") never
    reached the reviewer and prior_finding_context read missing although findings were answered.
    """

    local = finding_record(_semantic(7, origin=FindingOrigin.DETERMINISTIC), 11)
    answer = ResponseRecordedPayload(
        finding_id=fnd(7),
        finding_frontier=FRONTIER,
        disposition=ResponseDisposition.ACKNOWLEDGED,
        reason="The report file cannot honestly be populated: no variant qualifies.",
    )
    case = _build(
        _numba_case(
            extra_findings={fnd(7): local},
            extra_responses={fnd(7): record(answer, 17)},
        )
    )
    structural = _row(case, f"local-finding-answer-{fnd(7)}")
    assert structural["rulable"] is False
    assert structural["schema"] == "yoetz.local-finding-answer/1"
    assert structural["disposition"] == "acknowledged"
    texts = {item.item_id: item.content.decode("utf-8") for item in case.items}
    assert "cannot honestly be populated" in texts[f"local-finding-answer-text-{fnd(7)}"]
    # Never offered for a ruling.
    assert f"prior-finding-{fnd(7)}" not in case.packet.prior_finding_item_ids
    assert str(fnd(7)) not in case.packet.prior_finding_refs


def test_a_settled_finding_is_carried_nameable_but_never_rulable() -> None:
    """Issue #980 (cargo 5, pretrain 11): a finding the agent answered ``acknowledged_not_done``
    was dropped from the packet, so the reviewer could not name it in ``restates`` and every
    re-raise minted a new id. It is carried as a non-rulable ``yoetz.settled-finding/1`` row the
    packet view reports as nameable, after the open findings and inside the section bounds."""

    from finishup.application.semantic_case import semantic_case_packet_view

    settled = finding_record(_semantic(7), 11)
    answer = ResponseRecordedPayload(
        finding_id=fnd(7),
        finding_frontier=FRONTIER,
        disposition=ResponseDisposition.ACKNOWLEDGED_NOT_DONE,
        reason="No single tour satisfies the MTOW limit.",
    )
    case = _build(
        _numba_case(
            extra_findings={fnd(7): settled},
            extra_responses={fnd(7): record(answer, 17)},
        )
    )
    structural = _row(case, f"settled-finding-{fnd(7)}")
    assert structural["rulable"] is False
    assert structural["schema"] == "yoetz.settled-finding/1"
    assert structural["disposition"] == "acknowledged_not_done"
    texts = {item.item_id: item.content.decode("utf-8") for item in case.items}
    assert "MTOW" in texts[f"settled-finding-response-{fnd(7)}"]
    assert f"prior-finding-{fnd(7)}" not in case.packet.prior_finding_item_ids
    assert str(fnd(7)) not in case.packet.prior_finding_refs
    view = semantic_case_packet_view(case)
    assert view.settled_finding_refs == frozenset({str(fnd(7))})
    assert str(fnd(7)) not in view.prior_finding_refs
    # The open findings keep their place ahead of it.
    ids = list(case.packet.prior_finding_item_ids)
    assert all(
        ids.index(f"settled-finding-{fnd(7)}") > ids.index(f"prior-finding-{ref}")
        for ref in case.packet.prior_finding_refs
    )


def _limitation_request(number: int) -> Finding:
    return replace(
        _semantic(number, challenge=_CHALLENGE),
        challenge=replace(_CHALLENGE, requested_next_step="state_unresolved_limitation"),
    )


def _with_limit_decision(
    case: DeterministicCase,
    extra_obligation: tuple[ObligationId, ObligationProjectionRecord] | None = None,
) -> DeterministicCase:
    """The case with a ``finishup-verification-limit`` decision on obl(1) (and one more obligation)."""

    obligations = dict(case.projection.obligations)
    allowed = set(case.allowed_ids)
    coverage = dict(case.coverage_by_ref)
    if extra_obligation is not None:
        obligations[extra_obligation[0]] = extra_obligation[1]
        allowed.add(extra_obligation[0])
        coverage[extra_obligation[0]] = BASE_COVERAGE
    return replace(
        case,
        projection=replace(
            case.projection,
            obligations=MappingProxyType(obligations),
            decisions=MappingProxyType({evt(20): limit_decision(20, obl(1))}),
        ),
        allowed_ids=frozenset(allowed),
        coverage_by_ref=coverage,
    )


def test_a_limitation_the_agent_disclosed_travels_as_already_disclosed() -> None:
    """tb4n3 RC-1 (Q4): the reviewer is told the limit it asked for was stated, so it does not
    ask again or rule the item as work; an undisclosed request stays an open question."""

    disclosed_answer = ResponseRecordedPayload(
        finding_id=fnd(7),
        finding_frontier=FRONTIER,
        disposition=ResponseDisposition.ACKNOWLEDGED,
        reason="The hidden accuracy reference is withheld by the task design.",
    )
    case = _build(
        _numba_case(
            extra_findings={
                fnd(7): finding_record(_limitation_request(7), 11),
                fnd(8): finding_record(_limitation_request(8), 12),
            },
            extra_responses={fnd(7): record(disclosed_answer, 17)},
        )
    )
    settled = _row(case, f"settled-finding-{fnd(7)}")
    assert settled["rulable"] is False
    assert settled["limitation_already_disclosed"] is True
    assert settled["limitation_disclosed_by"] == "respond_acknowledgement"
    assert f"prior-finding-{fnd(7)}" not in case.packet.prior_finding_item_ids
    # The request nobody disclosed is still an open question the reviewer may rule on.
    assert f"prior-finding-{fnd(8)}" in case.packet.prior_finding_item_ids
    assert "limitation_already_disclosed" not in _row(case, f"prior-finding-{fnd(8)}")


def test_a_limitation_disclosed_by_a_decision_line_is_carried_without_an_answer() -> None:
    case = _numba_case(extra_findings={fnd(7): finding_record(_limitation_request(7), 11)})
    built = _build(_with_limit_decision(case))
    row = _row(built, f"settled-finding-{fnd(7)}")
    assert row["limitation_already_disclosed"] is True
    assert row["limitation_disclosed_by"] == "verification_limit_decision"
    assert row["disposition"] == "none"
    assert f"prior-finding-{fnd(7)}" not in built.packet.prior_finding_item_ids


def test_disclosures_travel_in_one_agent_assertion_row() -> None:
    """tb4n3 RC-1 put each disclosure beside its obligation; n7 RC7 (#1108): there it read as
    FinishUP's standing and the reviewer deferred to it over the packet's own material. The
    disclosures now travel in one row, labelled as the agent's assertion (ADR-040 amendment)."""

    case = _numba_case()
    acknowledged = obligation_record(
        ObligationPublishedPayload(
            obl(2),
            "Match the hidden benchmark",
            "the hidden accuracy matches",
            ObligationStatus.ACKNOWLEDGED_NOT_DONE,
            acknowledged_not_done_reason="The hidden benchmark is withheld by the task design.",
        ),
        3,
    )
    plain = _build(case)
    assert AGENT_DISCLOSURES_ITEM_ID not in {item.item_id for item in plain.items}
    built = _build(_with_limit_decision(case, extra_obligation=(obl(2), acknowledged)))
    for item in built.items:
        if item.section == "obligation":
            assert "yoetz_already_disclosed" not in _row(built, item.item_id), item.item_id
    assert built.packet.decision_item_ids[0] == AGENT_DISCLOSURES_ITEM_ID
    item = next(item for item in built.items if item.item_id == AGENT_DISCLOSURES_ITEM_ID)
    assert item.section == "decision"
    assert item.category is DataCategory.OBLIGATION_TEXT
    assert item.source_kind == "obligation"
    assert set(item.linked_subject_refs) == {str(obl(1)), str(obl(2))}
    row = _row(built, AGENT_DISCLOSURES_ITEM_ID)
    assert row["schema"] == "yoetz.agent-disclosures/1"
    assert row["kind"] == "agent_disclosures"
    assert row["standing"] == "agent_assertion"
    assert row["not_listed_count"] == 0
    by_obligation = {
        cast(str, entry["obligation_id"]): entry
        for entry in cast(list[Mapping[str, JsonValue]], row["disclosures"])
    }
    assert list(by_obligation) == sorted(by_obligation, key=str.encode)
    by_decision = by_obligation[str(obl(1))]
    assert by_decision["already_disclosed"] is True
    assert "verification_limit" in by_decision
    assert by_obligation[str(obl(2))] == {
        "obligation_id": str(obl(2)),
        "acknowledged_not_done": True,
        "already_disclosed": True,
    }


def test_envelope_bounding_keeps_the_disclosures_while_an_obligation_travels() -> None:
    """#1108 review R2: bounding drops catalog rows from the tail, and the agent-disclosures row
    sits in the decision section after the claims and obligations, so it dropped first and an
    obligation could travel without its disclosure. It now stays while any obligation row does."""

    def row(item_id: str, section: str) -> JsonValue:
        return {"item_id": item_id, "section": section}

    envelope: dict[str, JsonValue] = {
        "item_catalog": [
            row("obligation-1", "obligation"),
            row("claim-1", "claim"),
            row(AGENT_DISCLOSURES_ITEM_ID, "decision"),
            row("decision-1", "decision"),
            row("timeline-1", "timeline"),
        ],
        "review_packet": {"decision_item_ids": [AGENT_DISCLOSURES_ITEM_ID, "decision-1"]},
    }
    order: list[str] = []
    while semantic_case_module._drop_catalog_row(envelope):  # pyright: ignore[reportPrivateUsage]
        remaining = {
            cast(str, cast(Mapping[str, JsonValue], item)["item_id"])
            for item in cast(list[JsonValue], envelope["item_catalog"])
        }
        order.append(
            next(
                item_id
                for item_id in (
                    "timeline-1",
                    "decision-1",
                    "claim-1",
                    "obligation-1",
                    AGENT_DISCLOSURES_ITEM_ID,
                )
                if item_id not in remaining and item_id not in order
            )
        )
        if "obligation-1" in remaining:
            assert AGENT_DISCLOSURES_ITEM_ID in remaining
    assert order == [
        "timeline-1",
        "decision-1",
        "claim-1",
        "obligation-1",
        AGENT_DISCLOSURES_ITEM_ID,
    ]


def test_unanswered_local_finding_is_not_carried() -> None:
    local = finding_record(_semantic(7, origin=FindingOrigin.DETERMINISTIC), 11)
    case = _build(_numba_case(extra_findings={fnd(7): local}))
    assert not any(item.item_id.startswith("local-finding-answer") for item in case.items)


def test_closing_review_request_builds_the_final_phase_and_records_it() -> None:
    """Issue #976: the closing review's phase is in the question set and the manifest."""

    routine = _build(_numba_case())
    assert routine.question_set[0].startswith("Review phase: routine.")
    assert routine.packet.input_manifest is not None
    assert routine.packet.input_manifest.review_phase == "routine"

    closing = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=_numba_case(),
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.GOAL_AWARE,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.GOAL_AWARE),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        final_review=True,
    )
    assert closing.question_set[0].startswith("Review phase: final. This is the closing review")
    assert closing.packet.input_manifest is not None
    assert closing.packet.input_manifest.review_phase == "final"
    assert closing.case_digest != routine.case_digest


def test_closing_review_with_one_withheld_item_keeps_a_valid_final_manifest() -> None:
    """Issue #979 (tb4n1 fin-saccr S, tb4v2 pretrain S).

    A packet item withheld by the never-send heuristic is an omission row with reason
    ``never_send_heuristic``. Copying that reason verbatim into the provider-bound manifest's
    closed section vocabulary made the manifest undecodable, which dropped ``review_phase`` so the
    closing review was never recorded as final. The section now records ``redacted_never_send``.
    """

    from finishup.application.semantic_case import (
        REVIEW_PACKET_ITEM_ID,
        assemble_filtered_review_packet,
        bounded_case_envelope,
        review_packet_disclosure_result,
    )

    closing = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=_numba_case(),
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.GOAL_AWARE,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.GOAL_AWARE),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        final_review=True,
    )
    content = {item.item_id: item.content for item in closing.items}
    withheld = next(item_id for item_id in content if item_id.startswith("prior-finding-fnd_"))
    included = {*content, REVIEW_PACKET_ITEM_ID} - {withheld}
    envelope = strict_json_parse(bounded_case_envelope(closing))
    assert isinstance(envelope, dict)
    prepared = assemble_filtered_review_packet(
        cast(dict[str, object], envelope),
        content_by_id={key: value for key, value in content.items() if key in included},
        included_item_ids=included,
        withheld_item_ids={withheld},
    )
    packet = strict_json_parse(prepared)
    assert isinstance(packet, dict)
    review_packet = cast(dict[str, JsonValue], packet["review_packet"])
    assert any(
        isinstance(row, dict) and row.get("reason") == "never_send_heuristic"
        for row in cast(list[JsonValue], review_packet["omissions"])
    )
    result = review_packet_disclosure_result(prepared)
    assert result.failure is None
    manifest = cast(dict[str, JsonValue], review_packet["provider_input_manifest"])
    assert manifest["review_phase"] == "final"
    section = cast(dict[str, JsonValue], manifest["prior_finding_context"])
    reasons = cast(list[JsonValue], section["omission_reasons"])
    assert "redacted_never_send" in reasons
    assert "never_send_heuristic" not in reasons


def test_twelve_open_reviewer_findings_are_all_carried() -> None:
    """TB4 tb4n1 D10 (issue #976): eight was the cap, and six attempts dropped open findings.

    A task with twelve open reviewer findings, each with full challenge prose, carries every one
    of them to the next reviewer, in the case and in the bytes the provider receives, and the
    rulable list names each once, newest first.
    """

    extra = {
        fnd(number): finding_record(_semantic(number, challenge=_CHALLENGE), 20 + number)
        for number in range(3, 13)
    }
    case = _build(_numba_case(extra))

    expected = tuple(str(fnd(number)) for number in range(12, 0, -1))
    assert case.packet.prior_finding_refs == expected
    assert SEMANTIC_PRIOR_FINDINGS_OVER_LIMIT_GAP not in case.packet.coverage.known_gaps
    payload = cast(
        Mapping[str, JsonValue],
        strict_json_parse(
            semantic_case_to_prepared_payload(case, {item.item_id for item in case.items})
        ),
    )
    packet = cast(Mapping[str, JsonValue], payload["review_packet"])
    assert packet["prior_finding_refs"] == list(expected)


def test_over_the_limit_the_newest_open_findings_win_and_terminal_ones_never_compete() -> None:
    """Issue #976: past sixteen, the newest open findings are carried; a terminal one is never."""

    extra: dict[FindingId, FindingProjectionRecord] = {
        fnd(number): finding_record(_semantic(number, challenge=_CHALLENGE), 20 + number)
        for number in range(3, 3 + MAX_PRIOR_FINDINGS)
    }
    # The newest finding is final (acknowledged_not_done): it is history, not a live question.
    newest = 3 + MAX_PRIOR_FINDINGS
    extra[fnd(newest)] = finding_record(_semantic(newest, challenge=_CHALLENGE), 90)
    done = ResponseRecordedPayload(
        finding_id=fnd(newest),
        finding_frontier=FRONTIER,
        disposition=ResponseDisposition.ACKNOWLEDGED_NOT_DONE,
        reason="The package index is unreachable from this sandbox; not done.",
    )
    case = _build(_numba_case(extra, {fnd(newest): record(done, 91)}))

    carried = case.packet.prior_finding_refs
    assert len(carried) == MAX_PRIOR_FINDINGS == 16
    assert str(fnd(newest)) not in carried
    assert carried == tuple(str(fnd(number)) for number in range(newest - 1, 2, -1))


def _disclosed_obligations(count: int) -> DeterministicCase:
    """``count`` obligations, each covered by its own finishup-verification-limit decision."""

    case = _numba_case()
    obligations = dict(case.projection.obligations)
    decisions: dict[EventId, DecisionProjectionRecord] = {}
    allowed = set(case.allowed_ids)
    coverage = dict(case.coverage_by_ref)
    for number in range(1, count + 1):
        obligations[obl(number)] = obligation_record(
            ObligationPublishedPayload(
                obl(number), f"Obligation {number}", "criteria", ObligationStatus.OPEN
            ),
            2,
        )
        decisions[evt(40 + number)] = limit_decision(40 + number, obl(number))
        for ref in (obl(number), evt(40 + number)):
            allowed.add(ref)
            coverage[ref] = BASE_COVERAGE
    return replace(
        case,
        projection=replace(
            case.projection,
            obligations=MappingProxyType(obligations),
            decisions=MappingProxyType(decisions),
        ),
        allowed_ids=frozenset(allowed),
        coverage_by_ref=coverage,
    )


def test_every_carried_disclosure_reaches_the_reviewer_at_the_obligation_cap() -> None:
    """#1108 review R1: the row was held to the 4 KiB prose bound, so past about 26 disclosed
    obligations the rest were only counted, and it listed obligations the 32-row cap had dropped.
    It now uses the per-item bound and names exactly the obligations the packet carries."""

    built = _build(_disclosed_obligations(40))

    carried = set(built.packet.obligation_item_ids)
    assert len(carried) == 32
    row = _row(built, AGENT_DISCLOSURES_ITEM_ID)
    listed = {
        f"obligation-{cast(str, entry['obligation_id'])}"
        for entry in cast(list[Mapping[str, JsonValue]], row["disclosures"])
    }
    assert listed == carried
    assert row["not_listed_count"] == 0
    item = next(item for item in built.items if item.item_id == AGENT_DISCLOSURES_ITEM_ID)
    assert item.content_bytes > 4_096


def test_the_decision_the_disclosures_row_displaces_is_disclosed() -> None:
    """#1108 review R1: the row takes one of the 16 decision slots, so with 16 decisions the last
    one was dropped by the cap with nothing saying so. A capped decision is now an omission."""

    built = _build(_disclosed_obligations(16))

    assert built.packet.decision_item_ids[0] == AGENT_DISCLOSURES_ITEM_ID
    assert len(built.packet.decision_item_ids) == 16
    assert f"decision-{evt(56)}" not in built.packet.decision_item_ids
    assert any(
        row.subject_ref == str(evt(56))
        and row.reason == "not_selected"
        and row.category is DataCategory.DECISION_EXCERPT
        for row in built.packet.omissions
    )
