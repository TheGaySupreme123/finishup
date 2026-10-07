"""The prior-findings section carries the review dialogue into the next review (issue #905).

The reviewer has no memory between checks. Before this section, earlier findings and the main
agent's answers reached it only as raw timeline rows inside the last 64 events, which hook rows
pushed out, and the stored finding had lost what the reviewer asked for. These tests pin the
bounded, ledger-backed section that replaces that accident.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import cast

import pytest

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
from yoetz.application.semantic_case import (
    MAX_PRIOR_FINDINGS,
    build_semantic_case,
    semantic_case_to_prepared_payload,
)
from yoetz.domain.events import (
    EvidenceKind,
    EvidenceRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    ResponseDisposition,
    ResponseRecordedPayload,
    ResultOutcome,
    ResultRecordedPayload,
)
from yoetz.domain.findings import (
    Finding,
    FindingChallenge,
    FindingKind,
    FindingOrigin,
    SamplingParams,
    SemanticDispatchKind,
    SemanticProvenance,
)
from yoetz.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from yoetz.domain.receipts import SEMANTIC_PRIOR_FINDINGS_OVER_LIMIT_GAP
from yoetz.domain.values import FindingId, timestamp_from_string
from yoetz.kernel.deterministic_checks import DeterministicCase
from yoetz.kernel.projections import FindingProjectionRecord, ProjectionRecord
from yoetz.ports.semantic import SemanticCase
from yoetz.protocol.canonical import JsonValue, strict_json_parse
from yoetz.protocol.coverage import EvidenceImmutability
from yoetz.protocol.models import DataCategory, SemanticReason, SemanticStatus

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

    from yoetz.application.semantic_case import (
        _drop_prior_finding_rows,  # pyright: ignore[reportPrivateUsage]
    )
    from yoetz.domain.privacy import MAX_EGRESS_ENVELOPE_BYTES
    from yoetz.protocol.canonical import canonical_encode

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

    from yoetz.application.semantic_case import (
        _drop_prior_finding_rows,  # pyright: ignore[reportPrivateUsage]
    )
    from yoetz.domain.privacy import MAX_EGRESS_ENVELOPE_BYTES
    from yoetz.protocol.canonical import canonical_encode

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

    from yoetz.application.semantic_case import (
        _drop_prior_finding_rows,  # pyright: ignore[reportPrivateUsage]
    )
    from yoetz.domain.privacy import MAX_EGRESS_ENVELOPE_BYTES
    from yoetz.protocol.canonical import canonical_encode

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

    from yoetz.application import semantic_case as module
    from yoetz.domain.privacy import MAX_EGRESS_ENVELOPE_BYTES
    from yoetz.protocol.canonical import canonical_encode

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
    from yoetz.application import semantic_case as module
    from yoetz.protocol.canonical import canonical_encode

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
    """TB4 tb4f1 atrx (issue #976): the agent's answer to Yoetz's own finding reaches the review.

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

    from yoetz.application.semantic_case import semantic_case_packet_view

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
