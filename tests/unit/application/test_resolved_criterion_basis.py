"""A resolved obligation is one question: criterion, claim, observation, gap (issue #1079).

The basis rides the obligation item the policy already sends. It names refs inside the fence and
closed tokens. It does not copy a command, a summary, or a path, and an open obligation is unchanged.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import cast

from builders.policy_cases import (
    act,
    evd,
    evidence_record,
    make_case,
    obl,
    obligation_record,
    record,
    res,
)
from finishup.application.semantic_case import (
    build_semantic_case,
    semantic_case_to_prepared_payload,
)
from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    EvidenceContentAvailability,
    EvidenceDigestBinding,
    EvidenceDigestProvenance,
    EvidenceDigestSubject,
    EvidenceKind,
    EvidenceRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    ResultOutcome,
    ResultRecordedPayload,
)
from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from finishup.domain.values import (
    EvidenceId,
    ResultId,
    object_id,
    timestamp_from_string,
)
from finishup.kernel.deterministic_checks import DeterministicCase
from finishup.kernel.projections import EvidenceProjectionRecord, ProjectionRecord
from finishup.ports.semantic import SemanticCase
from finishup.protocol.canonical import JsonValue, strict_json_parse
from finishup.protocol.coverage import EvidenceImmutability
from finishup.protocol.models import DataCategory

_WHEN = timestamp_from_string("2026-10-15T12:00:00.000Z")
_SECRET_SUMMARY = "CLAIMED_RESULT_SUMMARY_MUST_STAY_OUT"
_SECRET_OUTPUT = "CAPTURED_STDOUT_MUST_STAY_OUT"
_SECRET_COMMAND = "pytest -q SECRET_COMMAND"
_UNRELATED = "UNRELATED_COMMAND_OUTPUT"


def _hook(
    number: int, frontier: int, description: str = _SECRET_OUTPUT
) -> EvidenceProjectionRecord:
    return evidence_record(
        EvidenceRecordedPayload(
            evd(number),
            EvidenceKind.OTHER,
            EvidenceImmutability.IMMUTABLE_SNAPSHOT,
            _WHEN,
            captured_object_id=object_id(f"obj_00000000-0000-4000-8000-{number:012x}"),
            content_digest="sha256:" + f"{number:064x}",
            description=description,
            digest_binding=EvidenceDigestBinding(
                subject=EvidenceDigestSubject.BOUNDED_EXCERPT,
                content_availability=EvidenceContentAvailability.CAPTURED,
                byte_count=4,
                provenance=EvidenceDigestProvenance.OBSERVATION_CAPTURED,
            ),
        ),
        frontier,
    )


def _asserted(number: int, frontier: int) -> EvidenceProjectionRecord:
    return evidence_record(
        EvidenceRecordedPayload(
            evd(number),
            EvidenceKind.OTHER,
            EvidenceImmutability.IMMUTABLE_SNAPSHOT,
            _WHEN,
            captured_object_id=object_id(f"obj_00000000-0000-4000-8000-{number:012x}"),
            content_digest="sha256:" + f"{number:064x}",
            description="caller asserted this output",
            digest_binding=EvidenceDigestBinding(
                subject=EvidenceDigestSubject.BOUNDED_EXCERPT,
                content_availability=EvidenceContentAvailability.CAPTURED,
                byte_count=4,
                provenance=EvidenceDigestProvenance.CALLER_ASSERTED,
            ),
        ),
        frontier,
    )


def _build(
    case: DeterministicCase,
    profile: ReviewContextProfile = ReviewContextProfile.GOAL_AWARE,
) -> SemanticCase:
    return build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=profile,
        review_selection=ReviewSelectionPolicy.for_profile(profile),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
    )


def _basis(case: DeterministicCase, obligation: int = 1) -> Mapping[str, JsonValue]:
    built = _build(case)
    item = next(item for item in built.items if item.item_id == f"obligation-{obl(obligation)}")
    assert item.category is DataCategory.OBLIGATION_TEXT
    body = cast(Mapping[str, JsonValue], strict_json_parse(item.content))
    return cast(Mapping[str, JsonValue], body["resolved_basis"])


def _resolved_case(
    *,
    evidence: dict[EvidenceId, EvidenceProjectionRecord] | None = None,
    evidence_refs: tuple[EvidenceId, ...] | None = None,
    summary: str = _SECRET_SUMMARY,
    extra_results: (dict[ResultId, ProjectionRecord[ResultRecordedPayload]] | None) = None,
    resolution: tuple[EvidenceId | ResultId, ...] | None = None,
) -> DeterministicCase:
    observed = {evd(1): _hook(1, 11)} if evidence is None else evidence
    cited = (evd(1),) if evidence_refs is None else evidence_refs
    result = record(
        ResultRecordedPayload(
            res(1),
            act(1),
            ResultOutcome.SUCCESS,
            summary=summary,
            evidence_refs=cited,
        ),
        20,
    )
    results: dict[ResultId, ProjectionRecord[ResultRecordedPayload]] = {res(1): result}
    if extra_results is not None:
        results.update(extra_results)
    resolution_refs: tuple[EvidenceId | ResultId, ...] = (
        (res(1),) if resolution is None else resolution
    )
    obligation = obligation_record(
        ObligationPublishedPayload(
            obl(1),
            "Reject a negative count",
            "the command exits 0",
            ObligationStatus.RESOLVED,
            resolution_evidence_refs=resolution_refs,
        ),
        2,
    )
    return make_case(
        obligations={obl(1): obligation},
        actions={
            act(1): record(
                ActionRecordedPayload(act(1), ActionKind.COMMAND, "ran", command=_SECRET_COMMAND),
                10,
            )
        },
        results=results,
        evidence=observed,
    )


def _obligation_text(case: DeterministicCase) -> str:
    built = _build(case)
    item = next(item for item in built.items if item.item_id == f"obligation-{obl(1)}")
    return item.content.decode("utf-8")


def test_a_resolved_obligation_names_the_result_and_the_newest_capture() -> None:
    evidence = {
        evd(1): _hook(1, 11),
        evd(2): _hook(2, 31),
        evd(3): _hook(3, 21),
        evd(4): _hook(4, 41),
        evd(5): _hook(5, 51),
        evd(8): _asserted(8, 61),
        evd(9): _hook(9, 71, description=_UNRELATED),
    }
    unrelated = record(
        ResultRecordedPayload(
            res(9),
            act(9),
            ResultOutcome.SUCCESS,
            summary=_UNRELATED,
            evidence_refs=(evd(9),),
        ),
        72,
    )
    case = _resolved_case(
        evidence=evidence,
        evidence_refs=(evd(1), evd(2), evd(3), evd(4), evd(5), evd(8)),
        extra_results={res(9): unrelated},
    )

    basis = _basis(case)
    assert basis["claimed_result_refs"] == [str(res(1))]
    assert basis["latest_observed_verification_refs"] == [
        str(evd(5)),
        str(evd(4)),
        str(evd(2)),
        str(evd(3)),
    ]
    assert basis["missing_input"] == []
    text = _obligation_text(case)
    for secret in (_SECRET_SUMMARY, _SECRET_OUTPUT, _SECRET_COMMAND, _UNRELATED):
        assert secret not in text
    assert str(evd(1)) not in text
    assert str(evd(8)) not in text
    assert str(evd(9)) not in text
    assert str(res(9)) not in text


def test_a_result_without_observed_output_names_the_missing_verification() -> None:
    case = _resolved_case(evidence={evd(1): _asserted(1, 11)}, evidence_refs=(evd(1),))

    basis = _basis(case)
    assert basis["claimed_result_refs"] == [str(res(1))]
    assert basis["latest_observed_verification_refs"] == []
    assert basis["missing_input"] == ["verification_output"]
    assert "caller asserted this output" not in _obligation_text(case)


def test_an_open_obligation_has_no_resolved_basis() -> None:
    case = make_case(
        obligations={
            obl(1): obligation_record(
                ObligationPublishedPayload(
                    obl(1), "Reject a negative count", "tests pass", ObligationStatus.OPEN
                ),
                2,
            )
        }
    )
    item = next(item for item in _build(case).items if item.item_id == f"obligation-{obl(1)}")
    body = cast(Mapping[str, JsonValue], strict_json_parse(item.content))
    assert "resolved_basis" not in body
    assert body["status"] == "open"


def test_redacted_or_unfenced_evidence_is_not_named() -> None:
    redacted = replace(_hook(1, 11), payload=None, redacted=True)
    case = _resolved_case(evidence={evd(1): redacted}, evidence_refs=(evd(1),))
    basis = _basis(case)
    assert basis["claimed_result_refs"] == [str(res(1))]
    assert basis["latest_observed_verification_refs"] == []
    assert basis["missing_input"] == ["verification_output"]

    readable = _resolved_case()
    fenced = replace(
        readable,
        allowed_ids=frozenset(ref for ref in readable.allowed_ids if ref != evd(1)),
        coverage_by_ref={
            ref: coverage for ref, coverage in readable.coverage_by_ref.items() if ref != evd(1)
        },
    )
    withheld = _basis(fenced)
    assert withheld["claimed_result_refs"] == [str(res(1))]
    assert withheld["latest_observed_verification_refs"] == []
    assert withheld["missing_input"] == ["verification_output"]
    assert str(evd(1)) not in _obligation_text(fenced)


def test_a_redacted_result_does_not_lend_its_capture() -> None:
    captured = _hook(1, 11)
    case = _resolved_case(evidence={evd(1): captured})
    hidden = replace(
        case,
        projection=replace(
            case.projection,
            results={res(1): replace(case.projection.results[res(1)], payload=None, redacted=True)},
        ),
    )
    basis = _basis(hidden)
    assert basis["claimed_result_refs"] == []
    assert basis["latest_observed_verification_refs"] == []
    assert basis["missing_input"] == ["claimed_result", "verification_output"]
    assert str(evd(1)) not in _obligation_text(hidden)
    assert _SECRET_SUMMARY not in _obligation_text(hidden)


def test_a_result_outside_the_fence_is_not_a_claimed_result() -> None:
    case = _resolved_case()
    fenced = replace(
        case,
        allowed_ids=frozenset(ref for ref in case.allowed_ids if ref != res(1)),
        coverage_by_ref={
            ref: coverage for ref, coverage in case.coverage_by_ref.items() if ref != res(1)
        },
    )
    basis = _basis(fenced)
    # The obligation still records the ref it was resolved by. The basis does not treat that
    # unfenced result as a readable claim, and it does not walk the result's capture.
    assert basis["claimed_result_refs"] == []
    assert basis["latest_observed_verification_refs"] == []
    assert basis["missing_input"] == ["claimed_result", "verification_output"]
    text = _obligation_text(fenced)
    assert str(evd(1)) not in text
    assert _SECRET_SUMMARY not in text
    assert _SECRET_COMMAND not in text


def test_observed_evidence_cited_directly_is_verification_without_a_claim() -> None:
    case = _resolved_case(evidence={evd(1): _hook(1, 11)}, resolution=(evd(1),))
    basis = _basis(case)
    assert basis["claimed_result_refs"] == []
    assert basis["latest_observed_verification_refs"] == [str(evd(1))]
    assert basis["missing_input"] == ["claimed_result"]


def test_claimed_results_stop_at_sixteen_refs() -> None:
    results = {
        res(number): record(
            ResultRecordedPayload(res(number), act(number), ResultOutcome.SUCCESS),
            20 + number,
        )
        for number in range(1, 18)
    }
    refs = tuple(
        sorted((res(number) for number in range(1, 18)), key=lambda item: str(item).encode())
    )
    obligation = obligation_record(
        ObligationPublishedPayload(
            obl(1),
            "Reject a negative count",
            "the command exits 0",
            ObligationStatus.RESOLVED,
            resolution_evidence_refs=refs,
        ),
        2,
    )
    case = make_case(obligations={obl(1): obligation}, results=results)
    kept = sorted((str(res(number)) for number in range(1, 18)), key=str.encode)[:16]
    basis = _basis(case)
    assert basis["claimed_result_refs"] == kept
    assert len(cast(list[JsonValue], basis["claimed_result_refs"])) == 16
    assert basis["missing_input"] == ["verification_output"]


def test_a_structural_profile_sends_no_basis() -> None:
    built = _build(_resolved_case(), ReviewContextProfile.STRUCTURAL)
    assert all(item.section != "obligation" for item in built.items)
    assert all(b"resolved_basis" not in item.content for item in built.items)
    assert all(_SECRET_SUMMARY.encode() not in item.content for item in built.items)


def test_withholding_obligation_text_withholds_the_basis() -> None:
    built = _build(_resolved_case())
    included = {
        item.item_id for item in built.items if item.category is not DataCategory.OBLIGATION_TEXT
    }
    payload = semantic_case_to_prepared_payload(built, included)
    assert b"resolved_basis" not in payload
    assert _SECRET_SUMMARY.encode() not in payload
    assert _SECRET_COMMAND.encode() not in payload
